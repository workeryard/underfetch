/**
 * `/reuse`: how many connections a session spends on requests to one place,
 * kept or not, and whether one kept across invocations still answers.
 */

import { profiles, type ProfileName } from '../src/fingerprint/profiles';
import { Session } from '../src/client/session';
import { decoders, dial, impersonating } from '../src/workers/index';

/** Kept between invocations, for `/reuse?global=1`, with its dial count. */
let kept: { session: Session; dials: { count: number } } | undefined;

/**
 * How many connections a session spends: requests one after another, then
 * several at once, with every dial counted. `global=1` uses a session kept
 * from an earlier invocation, whose sockets this one may not touch.
 */
export async function reuse(query: URLSearchParams) {
  const as = (query.get('as') ?? 'chrome') as ProfileName;
  const url = query.get('url') ?? 'https://httpbin.org/get';
  const n = Math.min(Number(query.get('n') ?? 4), 40);
  const keepAlive = query.get('keepAlive') !== '0';
  const fresh = () => {
    const dials = { count: 0 };
    const session = new Session({
      dial: (hostname, port) => {
        dials.count += 1;
        return dial(hostname, port);
      },
      tls: impersonating(profiles[as]),
      impersonate: profiles[as],
      decoders,
      timeoutMs: 20_000,
      keepAlive,
    });
    return { session, dials };
  };
  const { session, dials } = query.get('global') === '1' ? (kept ??= fresh()) : fresh();
  const before = dials.count;
  const one = async () => {
    const started = Date.now();
    try {
      const response = await session.get(url);
      await response.text();
      return { status: response.status, ms: Date.now() - started };
    } catch (error) {
      return { error: String(error), ms: Date.now() - started };
    }
  };
  const started = Date.now();
  const sequential = [];
  for (let i = 0; i < n; i++) sequential.push(await one());
  const together = await Promise.all(Array.from({ length: n }, one));
  return {
    as,
    url,
    keepAlive,
    dials: dials.count - before,
    totalMs: Date.now() - started,
    sequential,
    together,
  };
}
