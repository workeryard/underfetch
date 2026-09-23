/**
 * Following a chain of redirects around a transport that knows nothing of
 * them. Each hop is a fresh connection, so this belongs above the transport
 * rather than inside it.
 */

import { ApiError } from './request';

/** Statuses that name another place to look. */
const REDIRECTS = [301, 302, 303, 307, 308];

export interface RedirectOptions {
  /** Follow redirects. Default: true. */
  allowRedirects?: boolean | undefined;
  /** How many hops before giving up. Default: 20. */
  maxRedirects?: number | undefined;
}

/**
 * Follows redirects around `send`, which performs one request and knows
 * nothing about them. Each hop is a fresh connection, so this belongs above
 * the transport rather than inside it.
 */
export async function followRedirects(
  request: Request,
  send: (request: Request) => Promise<Response>,
  { allowRedirects = true, maxRedirects = 20 }: RedirectOptions = {},
  /**
   * Whether the body may be read into memory to send again. A streamed
   * upload may not: a 307 or 308, which would repeat it, is handed back to
   * the caller rather than followed.
   */
  replayable = true,
): Promise<Response> {
  // A 307 or 308 repeats the body, and a stream can only be sent once, so it
  // is read into memory before the first hop rather than lost on the second.
  const body =
    allowRedirects && replayable && request.body !== null
      ? new Uint8Array(await request.arrayBuffer())
      : null;
  let current = body === null ? request : new Request(request, { body: body as BodyInit });

  for (let hop = 0; ; hop++) {
    const response = await send(current);
    const location = response.headers.get('location');
    const repeatsBody = response.status === 307 || response.status === 308;
    if (
      !allowRedirects ||
      location === null ||
      !REDIRECTS.includes(response.status) ||
      (!replayable && current.body !== null && repeatsBody)
    ) {
      // The final URL is what the caller followed to, which a constructed
      // Response otherwise reports as empty.
      Object.defineProperty(response, 'url', { value: current.url, configurable: true });
      return response;
    }
    if (hop >= maxRedirects) {
      throw new ApiError(`gave up after ${maxRedirects} redirects`);
    }
    // The body is finished with; letting it dangle would hold the socket open.
    await response.body?.cancel().catch(() => undefined);
    current = redirected(current, response.status, new URL(location, current.url), body);
  }
}

/**
 * The next request in a chain. A 303, and a 301 or 302 answering anything but
 * GET or HEAD, become a GET without a body — which is what every client does,
 * whatever the older specifications said.
 */
function redirected(previous: Request, status: number, to: URL, body: Uint8Array | null): Request {
  const drops =
    status === 303 || ((status === 301 || status === 302) && previous.method !== 'HEAD');
  const headers = new Headers(previous.headers);
  // Credentials do not travel to another host.
  if (new URL(previous.url).origin !== to.origin) {
    headers.delete('authorization');
    headers.delete('cookie');
  }
  if (drops) {
    headers.delete('content-type');
    headers.delete('content-length');
    return new Request(to, { method: previous.method === 'HEAD' ? 'HEAD' : 'GET', headers });
  }
  return new Request(to, {
    method: previous.method,
    headers,
    ...(body === null ? {} : { body: body as BodyInit }),
  });
}
