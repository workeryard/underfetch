/**
 * A reusable client with settings of its own.
 *
 * `proxyFetch` takes everything on every call, which is right for a single
 * request and tedious for a hundred. A session remembers the proxy, the
 * timeout and the headers, and lets one request override any of them.
 */

import { proxyFetch } from './index';
import type { Dial, Proxy } from './socket';
import type { TlsFactory } from './tls';

export interface SessionDefaults {
  /** Where requests leave from. Left out, they are dialled directly. */
  proxy?: Proxy | undefined;
  /** Gives up after this many milliseconds. */
  timeoutMs?: number | undefined;
  /** Sent with every request, unless the request sets the header itself. */
  headers?: HeadersInit | undefined;
}

export interface SessionOptions extends SessionDefaults {
  /** Opens a plain TCP connection; the runtime supplies this. */
  dial: Dial;
  /** Builds a TLS client for one connection. */
  tls: TlsFactory;
}

export interface SessionRequestInit extends RequestInit {
  /** Overrides the session's proxy. `null` forces this one request direct. */
  proxy?: Proxy | null | undefined;
  timeoutMs?: number | undefined;
}

/** The session's headers, with anything the request set taking precedence. */
function merged(defaults: HeadersInit | undefined, request: Request): Headers {
  const headers = new Headers(request.headers);
  if (defaults === undefined) return headers;
  for (const [name, value] of new Headers(defaults)) {
    if (!headers.has(name)) headers.set(name, value);
  }
  return headers;
}

export class Session {
  readonly #dial: Dial;
  readonly #tls: TlsFactory;
  readonly #defaults: SessionDefaults;

  constructor({ dial, tls, ...defaults }: SessionOptions) {
    this.#dial = dial;
    this.#tls = tls;
    this.#defaults = defaults;
  }

  /** The proxy this session uses when a request does not say otherwise. */
  get proxy(): Proxy | undefined {
    return this.#defaults.proxy;
  }

  async fetch(input: string | URL | Request, init?: SessionRequestInit): Promise<Response> {
    const request = new Request(input, init);
    const headers = merged(this.#defaults.headers, request);
    // A request carrying session headers is a different request, so it is
    // rebuilt rather than mutated — `Request.headers` is not writable.
    const outgoing = new Request(request, { headers });

    // `null` is how a caller says "not through the session's proxy"; undefined
    // means they said nothing, so the session's own setting stands.
    const proxy = init?.proxy === undefined ? this.#defaults.proxy : (init.proxy ?? undefined);
    const timeoutMs = init?.timeoutMs ?? this.#defaults.timeoutMs;

    return proxyFetch(outgoing, {
      dial: this.#dial,
      tls: this.#tls,
      ...(proxy ? { proxy } : {}),
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
      ...(init?.signal ? { signal: init.signal } : {}),
    });
  }
}
