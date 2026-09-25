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
  /**
   * `Authorization`: a bearer token, or a username and password sent as
   * Basic, or as Digest with `type: 'digest'` — which costs a round trip,
   * since it answers the server's challenge.
   */
  auth?:
    | { bearer: string }
    | { username: string; password: string; type?: 'basic' | 'digest' | undefined }
    | undefined;
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
  // Digest cannot be written before the server's challenge; the session does it.
  const digest = auth !== undefined && 'type' in auth && auth.type === 'digest';
  if (auth !== undefined && !digest && !headers.has('authorization')) {
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
    // The Fetch standard asks for this with a stream body, and Node enforces
    // it; saying it here spares every caller.
    ...(body instanceof ReadableStream ? { duplex: 'half' } : {}),
  });
}
