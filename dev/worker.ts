/**
 * A Worker that checks the profiles against the outside world.
 *
 * `pnpm verify` proves the fingerprints from the bytes we generate, which is
 * enough for a regression. This is the second opinion: it makes a real request
 * through a real Cloudflare runtime and asks a server what it saw, which
 * catches what an offline check cannot — a runtime rewriting something
 * underneath us, or a profile that is right on paper and wrong on the wire.
 */

import { profiles, type ProfileName } from '../src/fingerprint/profiles';
import { withFingerprints } from '../src/fingerprint/custom';
import { akamai } from '../src/fingerprint/verify';
import { Session, timingOf, type Proxy, type Resource } from '../src/workers/index';
import { reuse } from './reuse';
import { cases } from './cases/http';
import { plainHttpCases, siteCases, tlsCases, websocketCases } from './cases/extra';
import { sessionCases } from './cases/session';
import { uploadCases } from './cases/uploads';
import { wafCases } from './cases/waf';
import { page, seen, type Outcome } from './cases/probe';

/** Reports back what the handshake and the HTTP/2 preface looked like. */
const CHECKER = 'https://tls.peet.ws/api/all';

interface Seen {
  http_version?: string;
  tls?: { ja4?: string };
  http2?: { akamai_fingerprint?: string };
}

async function check(name: ProfileName) {
  const profile = profiles[name];
  try {
    const response = await new Session({ impersonate: name, timeoutMs: 20_000 }).fetch(CHECKER);
    const seen = (await response.json()) as Seen;
    const ja4 = seen.tls?.ja4 ?? '';
    // The checker prints settings with semicolons; so does `akamai`.
    const observed = seen.http2?.akamai_fingerprint ?? '';
    return {
      name,
      http: seen.http_version,
      ja4: { seen: ja4, want: profile.expected.ja4, ok: ja4 === profile.expected.ja4 },
      akamai: {
        seen: observed,
        want: akamai(profile.http2),
        ok: observed === akamai(profile.http2),
      },
    };
  } catch (error) {
    return { name, error: String(error) };
  }
}

/**
 * What this costs against the platform's own `fetch`.
 *
 * `fetch` gets its TLS from the runtime, in native code, on a connection pool
 * it may already have warm. Here every handshake is done in WebAssembly on a
 * socket opened for this one request, so it is bound to be slower — the only
 * question is by how much, and that is a number rather than an opinion.
 */
async function time(label: string, run: () => Promise<Response>, rounds: number) {
  const samples: number[] = [];
  let failed: string | undefined;
  for (let i = 0; i < rounds; i++) {
    const started = Date.now();
    try {
      // Read to the end: a handshake that has not delivered a body is not done.
      await (await run()).text();
      samples.push(Date.now() - started);
    } catch (error) {
      failed = String(error);
      break;
    }
  }
  if (failed !== undefined) return { label, error: failed };
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    label,
    runs: samples,
    best: sorted[0],
    median: sorted[Math.floor(sorted.length / 2)],
    worst: sorted[sorted.length - 1],
  };
}

async function benchmark(url: string, rounds: number) {
  return [
    await time('platform fetch', () => fetch(url), rounds),
    await time('underfetch, no profile', () => new Session().fetch(url), rounds),
    await time(
      'underfetch, chrome',
      () => new Session({ impersonate: 'chrome' }).fetch(url),
      rounds,
    ),
  ];
}

/** The one binding the dev worker has: a local KV for /state/save and /state/load. */
interface Env {
  STATE: {
    get(key: string): Promise<string | null>;
    put(key: string, value: string): Promise<void>;
  };
  /** Set with `wrangler secret put PROBE_TOKEN` wherever this is deployed. */
  PROBE_TOKEN?: string;
}

/**
 * Every endpoint here fetches whatever it is told to, so deployed it is an
 * open proxy. Off localhost a request must carry the token, and with no token
 * configured nothing is served at all: it fails closed.
 */
async function allowed(request: Request, env: Env): Promise<boolean> {
  const host = new URL(request.url).hostname;
  if (host === 'localhost' || host === '127.0.0.1') return true;
  const expected = env.PROBE_TOKEN;
  const given = request.headers.get('x-probe-token');
  if (!expected || !given) return false;
  // Compare digests, so the time taken says nothing about the token.
  const digest = async (text: string) =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  const [a, b] = await Promise.all([digest(expected), digest(given)]);
  let differ = 0;
  for (let i = 0; i < a.length; i++) differ |= a[i]! ^ b[i]!;
  return differ === 0;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!(await allowed(request, env))) return new Response('not found', { status: 404 });
    const query = new URL(request.url).searchParams;

    // A session saved in one isolate and carried on in another: save, restart
    // the dev server, load. The first request after loading should resume TLS
    // and carry the cookie the saved session was given.
    if (new URL(request.url).pathname === '/state/save') {
      const as = (query.get('as') ?? undefined) as ProfileName | undefined;
      const session = new Session({ impersonate: as, cookies: true, timeoutMs: 20_000 });
      await (
        await session.get('https://httpbin.org/cookies/set/saved/yes', { allowRedirects: false })
      ).text();
      await (await session.get('https://tls.peet.ws/api/all')).text();
      const blob = session.marshal();
      await env.STATE.put('session', blob);
      return Response.json({ bytes: blob.length, state: JSON.parse(blob) as unknown });
    }
    if (new URL(request.url).pathname === '/state/load') {
      const blob = await env.STATE.get('session');
      if (blob === null)
        return new Response('nothing saved; call /state/save first', { status: 404 });
      const session = Session.unmarshal(blob, { timeoutMs: 20_000 });
      const seen = (await (await session.get('https://tls.peet.ws/api/all')).json()) as {
        tls?: { ja4?: string; extensions?: { name?: string }[] };
      };
      const cookies = (await (await session.get('https://httpbin.org/cookies')).json()) as unknown;
      return Response.json({
        ja4: seen.tls?.ja4,
        resumed: seen.tls?.extensions?.some((e) => e.name?.startsWith('pre_shared_key')) ?? false,
        cookies,
      });
    }

    if (new URL(request.url).pathname === '/bench') {
      const url = query.get('url') ?? 'https://example.com/';
      const rounds = Math.min(Number(query.get('n') ?? 5), 20);
      return Response.json({ url, rounds, results: await benchmark(url, rounds) });
    }

    if (new URL(request.url).pathname === '/custom') {
      // A profile from a JA3 and an Akamai string, checked against what a
      // server actually saw. The strings are tls.peet.ws's own field names.
      const base = (query.get('base') ?? 'chrome') as ProfileName;
      const strings = {
        ...(query.get('ja3') ? { ja3: query.get('ja3')! } : {}),
        ...(query.get('akamai') ? { akamai: query.get('akamai')! } : {}),
      };
      // What the session will claim, to compare with what the server saw.
      const as = withFingerprints(profiles[base], strings);
      const seen = (await (
        await new Session({ impersonate: base, ...strings, timeoutMs: 20_000 }).fetch(CHECKER)
      ).json()) as Seen & { tls?: { ja3?: string } };
      return Response.json({
        ja3: {
          want: as.expected.ja3,
          seen: seen.tls?.ja3,
          ok: as.expected.ja3 === undefined || as.expected.ja3 === seen.tls?.ja3,
        },
        ja4: {
          want: as.expected.ja4,
          seen: seen.tls?.ja4,
          ok: as.expected.ja4 === undefined || as.expected.ja4 === seen.tls?.ja4,
        },
        akamai: {
          want: as.expected.akamai,
          seen: seen.http2?.akamai_fingerprint,
          ok: as.expected.akamai === seen.http2?.akamai_fingerprint,
        },
      });
    }

    if (new URL(request.url).pathname === '/cases') {
      const as = (query.get('as') ?? undefined) as ProfileName | undefined;
      const only = query.get('only');
      const bin = query.get('bin') ?? 'https://httpbin.org';
      const suites = {
        http: () => cases(bin, as),
        plain: () => plainHttpCases(bin, as),
        session: () => sessionCases(as),
        uploads: () => uploadCases(bin, as),
        tls: () => tlsCases(as),
        sites: () => siteCases(as),
        websocket: () => websocketCases(as),
        waf: () => wafCases(as),
      };
      // `from` and `count` pick a page of the run, for a deployed Worker's
      // limit on connections per invocation; `cases` says how many there are.
      page(Number(query.get('from') ?? 0), Number(query.get('count') ?? Infinity));
      const all: Outcome[] = [];
      for (const [name, suite] of Object.entries(suites)) {
        if (only === null || only.split(',').includes(name)) all.push(...(await suite()));
      }
      const results = all.filter((r) => !r.skipped);
      const passed = results.filter((r) => r.ok).length;
      return Response.json({
        as: as ?? null,
        passed,
        total: results.length,
        cases: seen(),
        results,
      });
    }

    // Two requests through one session: the second should resume the first,
    // and tls.peet.ws shows the ClientHello it was sent each time. Each needs
    // a connection of its own to send one, so none is kept.
    if (new URL(request.url).pathname === '/resume') {
      const as = (query.get('as') ?? undefined) as ProfileName | undefined;
      const session = new Session({ impersonate: as, timeoutMs: 20_000, keepAlive: false });
      const hellos = [];
      for (let i = 0; i < 3; i++) {
        const seen = (await (await session.get('https://tls.peet.ws/api/all')).json()) as {
          tls?: { ja4?: string; extensions?: { name?: string }[] };
        };
        hellos.push({
          ja4: seen.tls?.ja4,
          psk: seen.tls?.extensions?.some((e) => e.name?.startsWith('pre_shared_key')) ?? false,
        });
      }
      return Response.json({ as: as ?? null, hellos });
    }

    if (new URL(request.url).pathname === '/reuse') {
      return Response.json(await reuse(query));
    }

    if (new URL(request.url).pathname === '/fetch') {
      const url = query.get('url');
      if (url === null) return new Response('give me ?url=', { status: 400 });
      const as = query.get('as') as ProfileName | null;
      const started = Date.now();
      // `?proxy=socks5://user:pass@host:1080`, and socks4, http, https alike.
      const via = query.get('proxy');
      const proxyUrl = via === null ? null : new URL(via);
      const proxy =
        proxyUrl === null
          ? undefined
          : ({
              kind: proxyUrl.protocol.slice(0, -1),
              hostname: proxyUrl.hostname,
              port: Number(proxyUrl.port),
              ...(proxyUrl.username ? { username: decodeURIComponent(proxyUrl.username) } : {}),
              ...(proxyUrl.password ? { password: decodeURIComponent(proxyUrl.password) } : {}),
            } as Proxy);
      let response: Response;
      try {
        response = await new Session({
          timeoutMs: 20_000,
          ...(as ? { impersonate: as } : {}),
          ...(proxy ? { proxy } : {}),
          ...(query.get('onCloudflare') === 'fetch' ? { onCloudflare: 'fetch' as const } : {}),
        }).fetch(url, {
          resource: (query.get('resource') ?? 'document') as Resource,
          ...(query.get('method') ? { method: query.get('method')! } : {}),
          ...(query.get('json') ? { json: JSON.parse(query.get('json')!) as unknown } : {}),
          ...(query.get('headers')
            ? { headers: JSON.parse(query.get('headers')!) as Record<string, string> }
            : {}),
        });
      } catch (error) {
        const e = error as Error & { permanent?: boolean };
        return Response.json(
          {
            status: 0,
            elapsedMs: Date.now() - started,
            error: `${e.name}: ${e.message}`,
            permanent: e.permanent ?? null,
            stack: e.stack?.split('\n').slice(0, 8),
          },
          { status: 502 },
        );
      }
      const body = await response.text();
      return Response.json({
        status: response.status,
        elapsedMs: Date.now() - started,
        timing: timingOf(response),
        headers: Object.fromEntries(response.headers),
        // `max` to read more of a page than a spot check needs.
        body: body.slice(0, Math.min(Number(query.get('max') ?? 700), 2_000_000)),
      });
    }

    const asked = query.get('as');
    const names = (asked ? [asked] : Object.keys(profiles)) as ProfileName[];
    const results = [];
    for (const name of names) results.push(await check(name));
    const ok = results.every((r) => 'ja4' in r && r.ja4.ok && r.akamai?.ok === true);
    return Response.json({ ok, results }, { status: ok ? 200 : 500 });
  },
};
