/**
 * Giving up on a request.
 *
 * Nothing below `fetch` has a timeout of its own: a socket that is never
 * answered would otherwise hang until the platform kills the whole invocation.
 * Closing the socket is what actually unblocks a pending read, so the signal is
 * wired to that rather than only to the promise the caller sees.
 */

export class TimeoutError extends Error {
  override name = 'TimeoutError';
}

/** Rejects when `signal` aborts, and never settles otherwise. */
export function aborted(signal: AbortSignal): Promise<never> {
  return new Promise<never>((_, reject) => {
    if (signal.aborted) {
      reject(signal.reason as Error);
      return;
    }
    signal.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
  });
}

/**
 * One signal for the caller's own, an optional deadline, and our own hand on
 * the switch. Returns the combined signal and the way to pull it.
 */
export function deadline(
  signal: AbortSignal | undefined,
  timeoutMs: number | undefined,
): { signal: AbortSignal; cancel: (reason: Error) => void } {
  const own = new AbortController();
  const parts: AbortSignal[] = [own.signal];
  if (signal) parts.push(signal);
  if (timeoutMs !== undefined && timeoutMs > 0) {
    parts.push(timeoutSignal(timeoutMs));
  }
  return {
    signal: parts.length === 1 ? own.signal : AbortSignal.any(parts),
    cancel: (reason) => own.abort(reason),
  };
}

/**
 * `AbortSignal.timeout` reports a `TimeoutError` whose message says nothing
 * about what timed out, so the duration is spelled out here instead.
 */
function timeoutSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(new TimeoutError(`the request took longer than ${ms}ms`)), ms);
  return controller.signal;
}

/** Runs `work`, rejecting early if the signal goes first. */
export function until<T>(signal: AbortSignal, work: Promise<T>): Promise<T> {
  return Promise.race([work, aborted(signal)]);
}
