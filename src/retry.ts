/**
 * Trying again, but only when trying again is safe.
 *
 * A proxied request crosses one more machine than a direct one, so a transport
 * failure is that much likelier and that much less meaningful. What is not
 * automatic is repeating a request that changed something: by default only
 * methods defined to be idempotent are retried, and a POST is left alone
 * unless the caller says otherwise.
 */

export interface RetryOptions {
  /** Attempts after the first. Default: 2. Zero turns retrying off. */
  limit?: number | undefined;
  /** Methods safe to repeat. Default: everything but POST and PATCH. */
  methods?: readonly string[] | undefined;
  /** Statuses worth repeating. Default: 408, 429 and the 5xx that mean "later". */
  statusCodes?: readonly number[] | undefined;
  /** Ceiling on a single wait, including one a server asked for. Default: 30s. */
  maxDelayMs?: number | undefined;
}

const DEFAULTS = {
  limit: 2,
  methods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'TRACE'],
  statusCodes: [408, 429, 500, 502, 503, 504],
  maxDelayMs: 30_000,
} as const;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** `Retry-After`, which is either seconds or an HTTP date. */
function askedFor(response: Response, now: number): number | null {
  const header = response.headers.get('retry-after');
  if (header === null) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const when = Date.parse(header);
  return Number.isNaN(when) ? null : Math.max(0, when - now);
}

/**
 * Exponential, with jitter. Without the jitter every client that failed
 * together comes back together, which is how a struggling server stays down.
 */
function backoff(attempt: number, ceiling: number): number {
  const window = Math.min(ceiling, 200 * 2 ** attempt);
  return Math.round(window / 2 + Math.random() * (window / 2));
}

/**
 * Runs `send`, repeating it while it fails in a way worth repeating. The body
 * is read once up front, because a stream cannot be sent twice.
 */
export async function withRetry(
  request: Request,
  send: (request: Request) => Promise<Response>,
  options: RetryOptions | number | false = {},
): Promise<Response> {
  // An explicit `undefined` in the options must not erase a default, which a
  // plain spread would do.
  const given =
    options === false ? { limit: 0 } : typeof options === 'number' ? { limit: options } : options;
  const settings = {
    limit: given.limit ?? DEFAULTS.limit,
    methods: given.methods ?? DEFAULTS.methods,
    statusCodes: given.statusCodes ?? DEFAULTS.statusCodes,
    maxDelayMs: given.maxDelayMs ?? DEFAULTS.maxDelayMs,
  };

  const repeatable = settings.methods.includes(request.method.toUpperCase());
  if (settings.limit <= 0 || !repeatable) return send(request);

  const body = request.body === null ? null : new Uint8Array(await request.arrayBuffer());
  const attempt = () =>
    body === null ? request.clone() : new Request(request, { body: body as BodyInit });

  let lastError: unknown;
  for (let tries = 0; ; tries++) {
    let response: Response | undefined;
    try {
      response = await send(attempt());
    } catch (error) {
      lastError = error;
      // An abort is the caller changing their mind, not a failure to retry.
      if (error instanceof Error && error.name === 'AbortError') throw error;
    }

    if (response !== undefined && !settings.statusCodes.includes(response.status)) {
      return response;
    }
    if (tries >= settings.limit) {
      if (response !== undefined) return response;
      throw lastError;
    }

    const now = Date.now();
    const wait = response === undefined ? null : askedFor(response, now);
    // A body left unread would hold its socket open while we wait.
    await response?.body?.cancel().catch(() => undefined);
    await sleep(Math.min(settings.maxDelayMs, wait ?? backoff(tries, settings.maxDelayMs)));
  }
}
