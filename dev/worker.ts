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
import { akamai } from '../src/fingerprint/verify';
import { Session } from '../src/workers/index';
import { cases } from './cases/http';
import { plainHttpCases, siteCases, tlsCases, websocketCases } from './cases/extra';
import type { Outcome } from './cases/probe';

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

export default {
  async fetch(request: Request): Promise<Response> {
    const query = new URL(request.url).searchParams;

    if (new URL(request.url).pathname === '/bench') {
      const url = query.get('url') ?? 'https://example.com/';
      const rounds = Math.min(Number(query.get('n') ?? 5), 20);
      return Response.json({ url, rounds, results: await benchmark(url, rounds) });
    }

    if (new URL(request.url).pathname === '/cases') {
      const as = (query.get('as') ?? undefined) as ProfileName | undefined;
      const only = query.get('only');
      const bin = query.get('bin') ?? 'https://httpbin.org';
      const suites = {
        http: () => cases(bin, as),
        plain: () => plainHttpCases(bin, as),
        tls: () => tlsCases(as),
        sites: () => siteCases(as),
        websocket: () => websocketCases(as),
      };
      const results: Outcome[] = [];
      for (const [name, suite] of Object.entries(suites)) {
        if (only === null || only.split(',').includes(name)) results.push(...(await suite()));
      }
      const passed = results.filter((r) => r.ok).length;
      return Response.json({ as: as ?? null, passed, total: results.length, results });
    }

    if (new URL(request.url).pathname === '/fetch') {
      const url = query.get('url');
      if (url === null) return new Response('give me ?url=', { status: 400 });
      const as = query.get('as') as ProfileName | null;
      const started = Date.now();
      const response = await new Session({
        timeoutMs: 20_000,
        ...(as ? { impersonate: as } : {}),
      }).fetch(url);
      const body = await response.text();
      return Response.json({
        status: response.status,
        elapsedMs: Date.now() - started,
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
