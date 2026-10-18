import { DialError } from '../net/socket';

/**
 * Why a connection could not be made, in words a caller can act on. A
 * deployed Worker may not open a TCP socket to Cloudflare's own addresses,
 * so a site served through Cloudflare cannot be reached from a Worker
 * without a proxy between them. `wrangler dev` does not enforce this;
 * production does.
 *
 * Production refuses it with "proxy request failed, cannot connect to the
 * specified address. It looks like you might be trying to connect to a
 * HTTP-based service — consider using fetch instead" (seen 2026-09-25). The
 * first half is also what any unreachable address gets, so only the second
 * marks the Cloudflare block, and only that is final: anything else may work
 * on another try.
 *
 * "Stream was cancelled." once counted too, from before `opened` was awaited,
 * when a read was what failed. It also comes from a connection that is
 * simply lost, and marked a site that was never behind Cloudflare as
 * blocked for good — with `onCloudflare: 'fetch'`, sent without the
 * profile's TLS. Seen on 2026-10-19 in `wrangler dev`, which blocks nothing.
 */
export function refused(hostname: string, port: number, error: unknown): DialError {
  const said = error instanceof Error ? error.message : String(error);
  if (/HTTP-based service/i.test(said)) {
    return new DialError(
      `could not connect to ${hostname}:${port}: a Worker may not open TCP connections to ` +
        "Cloudflare's own IP ranges, which is where a site behind Cloudflare lives. " +
        'Reach it through a proxy (the `proxy` option).',
      true,
      { cause: error },
    );
  }
  return new DialError(`could not connect to ${hostname}:${port}: ${said}`, false, {
    cause: error,
  });
}
