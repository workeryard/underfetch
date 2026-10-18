/**
 * How long a request's phases took, as measured — never estimated.
 *
 * A phase that did not happen, such as connecting on a kept connection, is
 * left out rather than given a zero or a share of the total; a number here
 * was read off the clock around the thing it names. The answer stays a plain
 * `Response`, so its timing is looked up with `timingOf` rather than hung on
 * it.
 *
 * In a Worker the clock moves only on I/O, so the CPU a phase spends — the
 * handshake's own cryptography, some 6 ms — is not in its number; the round
 * trips, which are nearly all of it, are.
 */

export interface Timing {
  /** When the request began, in milliseconds since the epoch. */
  start: number;
  /** It went on a connection already open, so nothing was dialled for it. */
  reused: boolean;
  /**
   * Opening the TCP connection, to the proxy when there is one. It includes
   * resolving the name: a Worker's `connect()` does both and cannot be split.
   */
  connect?: number | undefined;
  /** The proxy's handshake — SOCKS or CONNECT, and TLS to an HTTPS proxy. */
  proxy?: number | undefined;
  /** The TLS handshake with the target. */
  tls?: number | undefined;
  /** From `start` until the answer's status and headers had arrived. */
  firstByte: number;
  /** From `start` until the body was read to its end; unset until it is. */
  total?: number | undefined;
}

/** What opening a connection cost, phase by phase. */
export type Phases = Pick<Timing, 'connect' | 'proxy' | 'tls'>;

const timings = new WeakMap<Response, Timing>();

/**
 * How long `response` took, if it came over a connection of ours: one hop of
 * a redirect chain and one try of a retry, the one that answered. Undefined
 * for an answer that did not, such as the runtime's fetch as a fallback.
 * `total` fills in once the body has been read.
 */
export function timingOf(response: Response): Timing | undefined {
  return timings.get(response);
}

/**
 * Records `timing` for `response`, with a body that stamps `total` when it
 * has been read to its end. Returns the response the caller should be given.
 */
export function timed(response: Response, timing: Timing): Response {
  if (response.body === null) {
    timing.total = timing.firstByte;
    timings.set(response, timing);
    return response;
  }
  const reader = response.body.getReader();
  const body = new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        const { value, done } = await reader.read();
        if (done) {
          timing.total = Date.now() - timing.start;
          controller.close();
        } else {
          controller.enqueue(value);
        }
      },
      cancel: (reason) => reader.cancel(reason),
    },
    // Read only when asked: a wrapper reading ahead would drain the socket
    // before the caller wants the bytes, and undo HTTP/2's flow control.
    { highWaterMark: 0 },
  );
  const out = new Response(body, response);
  timings.set(out, timing);
  return out;
}
