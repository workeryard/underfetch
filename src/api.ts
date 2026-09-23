/**
 * The comfortable end of the library.
 *
 * `fetch(input, init)` is the whole Web platform in one call and stays the
 * escape hatch, but most requests are a URL, some query parameters and a JSON
 * body. These turn that into a `Request` without the caller assembling one.
 *
 * What comes back is a plain `Response`, deliberately: it already carries
 * `status`, `headers`, `text()` and `json()`, and unlike a bespoke response
 * object it leaves the body streaming, which is the point of this library.
 */

export type Params = Record<string, string | number | boolean> | URLSearchParams;

export interface BodyOptions {
  /** Query parameters, merged with any already in the URL. */
  params?: Params | undefined;
  /** A JSON body. Sets `content-type` unless the caller already did. */
  json?: unknown;
  /** A form body, sent as `application/x-www-form-urlencoded`. */
  form?: Record<string, string> | URLSearchParams | undefined;
  /** `Authorization`, as either scheme. */
  auth?: { bearer: string } | { username: string; password: string } | undefined;
}

export class ApiError extends Error {
  override name = 'ApiError';
}

function withParams(url: URL, params: Params | undefined): URL {
  if (params === undefined) return url;
  const extra = params instanceof URLSearchParams ? params : new URLSearchParams();
  if (!(params instanceof URLSearchParams)) {
    for (const [name, value] of Object.entries(params)) extra.append(name, String(value));
  }
  for (const [name, value] of extra) url.searchParams.append(name, value);
  return url;
}

function authorization(auth: NonNullable<BodyOptions['auth']>): string {
  if ('bearer' in auth) return `Bearer ${auth.bearer}`;
  return `Basic ${btoa(`${auth.username}:${auth.password}`)}`;
}

/**
 * Builds the request these options describe. `base` lets a session hold the
 * host so its callers can pass paths.
 */
export function buildRequest(
  input: string | URL | Request,
  init: (RequestInit & BodyOptions) | undefined,
  base?: string,
): Request {
  if (input instanceof Request && init === undefined) return input;

  const { params, json, form, auth, ...rest } = init ?? {};
  if (json !== undefined && form !== undefined) {
    throw new ApiError('a request has one body: json or form, not both');
  }

  const target = input instanceof Request ? input.url : input;
  const url = withParams(new URL(String(target), base), params);
  const headers = new Headers(
    rest.headers ?? (input instanceof Request ? input.headers : undefined),
  );

  let body = rest.body;
  if (json !== undefined) {
    body = JSON.stringify(json);
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  } else if (form !== undefined) {
    body = form instanceof URLSearchParams ? form : new URLSearchParams(form);
    if (!headers.has('content-type')) {
      headers.set('content-type', 'application/x-www-form-urlencoded');
    }
  }
  if (auth !== undefined && !headers.has('authorization')) {
    headers.set('authorization', authorization(auth));
  }

  const method = rest.method ?? (input instanceof Request ? input.method : 'GET');
  if (body !== undefined && body !== null && (method === 'GET' || method === 'HEAD')) {
    throw new ApiError(`a ${method} carries no body; give the request a method`);
  }
  return new Request(url, {
    ...rest,
    method,
    headers,
    ...(body === undefined ? {} : { body }),
  });
}

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
): Promise<Response> {
  // A 307 or 308 repeats the body, and a stream can only be sent once, so it
  // is read into memory before the first hop rather than lost on the second.
  const body =
    allowRedirects && request.body !== null ? new Uint8Array(await request.arrayBuffer()) : null;
  let current = body === null ? request : new Request(request, { body: body as BodyInit });

  for (let hop = 0; ; hop++) {
    const response = await send(current);
    const location = response.headers.get('location');
    if (!allowRedirects || location === null || !REDIRECTS.includes(response.status)) {
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
