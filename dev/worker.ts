/**
 * A Worker that checks the profiles against the outside world.
 *
 * `pnpm verify` proves the fingerprints from the bytes we generate, which is
 * enough for a regression. This is the second opinion: it makes a real request
 * through a real Cloudflare runtime and asks a server what it saw, which
 * catches what an offline check cannot — a runtime rewriting something
 * underneath us, or a profile that is right on paper and wrong on the wire.
 */

import { profiles, type ProfileName } from '../src/impersonate';
import { akamai } from '../src/verify';
import { Session } from '../src/workers/index';

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

export default {
  async fetch(request: Request): Promise<Response> {
    const asked = new URL(request.url).searchParams.get('as');
    const names = (asked ? [asked] : Object.keys(profiles)) as ProfileName[];
    const results = [];
    for (const name of names) results.push(await check(name));
    const ok = results.every((r) => 'ja4' in r && r.ja4.ok && r.akamai?.ok === true);
    return Response.json({ ok, results }, { status: ok ? 200 : 500 });
  },
};
