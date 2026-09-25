/**
 * A reusable client with settings of its own.
 *
 * `fetchOver` takes everything on every call, which is right for a single
 * request and tedious for a hundred. A session remembers the proxy, the
 * timeout and the headers, and lets one request override any of them.
 */

import { acceptable, type Decoders } from '../http/decompress';
import {
  headerOrder,
  resourceHeaders,
  resourceWeight,
  type FetchSite,
  type Resource,
} from '../fingerprint/order';
import type { Impersonation } from '../fingerprint/profiles';
import type { InflaterFactory } from '../http/permessage-deflate';
import type { Http2Profile } from '../http/h2/connection';
import type { Dial, Proxy } from '../net/socket';
import type { TlsFactory } from '../tls/tunnel';
import { CookieJar } from './cookies';
import { withDigest } from './digest';
import { fetchOver } from './fetch';
import { followRedirects, type RedirectOptions } from './redirects';
import { buildRequest, type BodyOptions } from './request';
import { withRetry, type RetryOptions } from './retry';
import { connectWebSocket, type WebSocketOptions } from './websocket';
import type { WebSocketConnection } from '../http/websocket';

export interface SessionDefaults extends RedirectOptions {
  /** Prefixed to a path, so callers can ask for `/v1/models`. */
  baseUrl?: string | undefined;
  /**
   * Keep cookies across requests. `true` makes a jar of its own; pass one to
   * share it, or to read what a server set. A jar is per-user state, so it is
   * never shared by default.
   */
  cookies?: boolean | CookieJar | undefined;
  /** Repeat a failed request. See `RetryOptions`; `false` turns it off. */
  retry?: RetryOptions | number | false | undefined;
  /** Where requests leave from. Left out, they are dialled directly. */
  proxy?: Proxy | undefined;
  /** Gives up after this many milliseconds. */
  timeoutMs?: number | undefined;
  /** Gives up on connecting after this many; see `FetchOverOptions`. */
  connectTimeoutMs?: number | undefined;
  /** Sent with every request, unless the request sets the header itself. */
  headers?: HeadersInit | undefined;
}

export interface SessionOptions extends SessionDefaults {
  /** Opens a plain TCP connection; the runtime supplies this. */
  dial: Dial;
  /** Builds a TLS client for one connection. */
  tls: TlsFactory;
  /** How to open an HTTP/2 connection, when ALPN settles on one. */
  http2?: Http2Profile | undefined;
  /**
   * The browser whose headers go with every request — in its order, and as
   * it sends them for the kind of request each is. Its HTTP/2 opening
   * replaces `http2`. The TLS side is `tls`'s business.
   */
  impersonate?: Impersonation | undefined;
  /** Decoders beyond gzip and deflate; the runtime supplies these. */
  decoders?: Decoders | undefined;
  /** Reads permessage-deflate on a WebSocket; the runtime supplies it. */
  inflater?: InflaterFactory | undefined;
}

export interface SessionWebSocketInit extends WebSocketOptions {
  /** Overrides the session's proxy. `null` forces this one direct. */
  proxy?: Proxy | null | undefined;
}

/**
 * What a browser sends only when it navigates, and not on a WebSocket's
 * Upgrade: a profile's headers are a page load's, so these stay behind.
 */
const NAVIGATION_ONLY = /^(sec-fetch-|sec-ch-ua|accept$|upgrade-insecure-requests$|priority$)/;

export interface SessionRequestInit extends RequestInit, BodyOptions, RedirectOptions {
  /** Overrides the session's proxy. `null` forces this one request direct. */
  proxy?: Proxy | null | undefined;
  timeoutMs?: number | undefined;
  connectTimeoutMs?: number | undefined;
  /** Overrides the session's retry policy for this one request. */
  retry?: RetryOptions | number | false | undefined;
  /**
   * What the request is, for a session that impersonates: a page load
   * (`document`, the default) or a script's call to an API (`fetch`), which a
   * browser sends with different headers, in a different order, at another
   * priority. Without a profile there is nothing to imitate and it is ignored.
   */
  resource?: Resource | undefined;
  /** For `fetch`: where the calling page stands. Default `same-origin`. */
  site?: FetchSite | undefined;
}

/**
 * The request's headers, then the session's, then the browser's: each fills
 * only what the ones before it left unset.
 */
function merged(request: Request, ...layers: (HeadersInit | undefined)[]): Headers {
  const headers = new Headers(request.headers);
  for (const layer of layers) {
    if (layer === undefined) continue;
    for (const [name, value] of new Headers(layer)) {
      if (!headers.has(name)) headers.set(name, value);
    }
  }
  return headers;
}

export class Session {
  readonly #dial: Dial;
  readonly #tls: TlsFactory;
  readonly #http2: Http2Profile | undefined;
  readonly #profile: Impersonation | undefined;
  readonly #decoders: Decoders | undefined;
  readonly #inflater: InflaterFactory | undefined;
  readonly #defaults: SessionDefaults;
  readonly #jar: CookieJar | undefined;

  constructor({ dial, tls, http2, impersonate, decoders, inflater, ...defaults }: SessionOptions) {
    this.#dial = dial;
    this.#tls = tls;
    this.#http2 = impersonate?.http2 ?? http2;
    this.#profile = impersonate;
    this.#decoders = decoders;
    this.#inflater = inflater;
    this.#defaults = defaults;
    this.#jar =
      defaults.cookies === true
        ? new CookieJar()
        : defaults.cookies instanceof CookieJar
          ? defaults.cookies
          : undefined;
  }

  /** The cookies this session is holding, if it was asked to hold any. */
  get cookies(): CookieJar | undefined {
    return this.#jar;
  }

  /** The proxy this session uses when a request does not say otherwise. */
  get proxy(): Proxy | undefined {
    return this.#defaults.proxy;
  }

  /**
   * The browser's headers for this kind of request, with an `accept-encoding`
   * cut to what this runtime can decode.
   */
  #browserHeaders(resource: Resource, site: FetchSite | undefined): Headers | undefined {
    if (this.#profile === undefined) return undefined;
    const headers = new Headers(
      resourceHeaders(this.#profile, resource, site) as [string, string][],
    );
    const offered = headers.get('accept-encoding');
    if (offered !== null) headers.set('accept-encoding', acceptable(offered, this.#decoders));
    return headers;
  }

  /** The HTTP/2 opening for this kind of request: a fetch() weighs less. */
  #http2For(resource: Resource): Http2Profile | undefined {
    const weight = this.#profile && resourceWeight(this.#profile, resource);
    const base = this.#http2;
    if (weight === undefined || base?.priority === undefined) return base;
    return { ...base, priority: { ...base.priority, weight } };
  }

  async fetch(input: string | URL | Request, init?: SessionRequestInit): Promise<Response> {
    const request = buildRequest(input, init, this.#defaults.baseUrl);
    const resource = init?.resource ?? 'document';
    const headers = merged(
      request,
      this.#defaults.headers,
      this.#browserHeaders(resource, init?.site),
    );
    const order = this.#profile && headerOrder(this.#profile, resource);
    const http2 = this.#http2For(resource);
    // A request carrying session headers is a different request, so it is
    // rebuilt rather than mutated — `Request.headers` is not writable.
    const outgoing = new Request(request, { headers });
    // A stream the caller handed us is sent as it arrives, never held in
    // memory: which also means it cannot be sent twice, by a retry or a 307.
    const streamed = init?.body instanceof ReadableStream;

    // `null` is how a caller says "not through the session's proxy"; undefined
    // means they said nothing, so the session's own setting stands.
    const proxy = init?.proxy === undefined ? this.#defaults.proxy : (init.proxy ?? undefined);
    const timeoutMs = init?.timeoutMs ?? this.#defaults.timeoutMs;
    const connectTimeoutMs = init?.connectTimeoutMs ?? this.#defaults.connectTimeoutMs;

    const once = (one: Request) =>
      fetchOver(one, {
        dial: this.#dial,
        tls: this.#tls,
        ...(http2 ? { http2 } : {}),
        ...(order ? { headerOrder: order } : {}),
        ...(this.#decoders ? { decoders: this.#decoders } : {}),
        ...(proxy ? { proxy } : {}),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
        ...(connectTimeoutMs === undefined ? {} : { connectTimeoutMs }),
        ...(init?.signal ? { signal: init.signal } : {}),
        ...(streamed ? { streamBody: true } : {}),
      });

    // Cookies belong around a single hop, so a redirect both sends what it
    // should and keeps whatever it is handed on the way.
    const jar = this.#jar;
    const send = async (one: Request) => {
      if (jar === undefined) return once(one);
      const url = new URL(one.url);
      const held = jar.header(url);
      const withCookies =
        held === null || one.headers.has('cookie')
          ? one
          : new Request(one, { headers: new Headers([...one.headers, ['cookie', held]]) });
      const response = await once(withCookies);
      jar.store(url, response.headers.getSetCookie());
      return response;
    };

    // Digest answers a challenge per hop, and only on the host it was meant for.
    const auth = init?.auth;
    const digest =
      auth !== undefined && 'type' in auth && auth.type === 'digest' ? auth : undefined;
    const origin = new URL(outgoing.url).origin;
    const authed = (one: Request) =>
      digest === undefined ? send(one) : withDigest(one, send, digest, origin, !streamed);

    const followed = (one: Request) =>
      followRedirects(
        one,
        authed,
        {
          allowRedirects: init?.allowRedirects ?? this.#defaults.allowRedirects,
          maxRedirects: init?.maxRedirects ?? this.#defaults.maxRedirects,
        },
        !streamed,
      );

    const retry = streamed ? false : (init?.retry ?? this.#defaults.retry ?? {});
    return withRetry(outgoing, followed, retry);
  }

  /**
   * Opens a WebSocket with the session's proxy, headers and cookies, over a
   * connection of its own — as a browser opens one, with ALPN `http/1.1`.
   */
  async websocket(
    url: string | URL,
    init: SessionWebSocketInit = {},
  ): Promise<WebSocketConnection> {
    const target = new URL(url, this.#defaults.baseUrl);
    const headers = new Headers(init.headers);
    for (const layer of [this.#defaults.headers, this.#browserHeaders('document', undefined)]) {
      for (const [name, value] of new Headers(layer)) {
        if (!headers.has(name) && !NAVIGATION_ONLY.test(name)) headers.set(name, value);
      }
    }
    // Cookies are scoped by the http(s) URL the ws(s) one stands for.
    const cookieUrl = new URL(target);
    cookieUrl.protocol =
      target.protocol === 'ws:' || target.protocol === 'http:' ? 'http:' : 'https:';
    const held = this.#jar?.header(cookieUrl) ?? null;
    if (held !== null && !headers.has('cookie')) headers.set('cookie', held);

    const proxy = init.proxy === undefined ? this.#defaults.proxy : (init.proxy ?? undefined);
    const timeoutMs = init.timeoutMs ?? this.#defaults.timeoutMs;
    const { socket, headers: answer } = await connectWebSocket(target, {
      ...init,
      headers,
      dial: this.#dial,
      tls: this.#tls,
      inflater: this.#inflater,
      connectTimeoutMs: init.connectTimeoutMs ?? this.#defaults.connectTimeoutMs,
      ...(proxy ? { proxy } : { proxy: undefined }),
      timeoutMs,
    });
    this.#jar?.store(cookieUrl, answer.getSetCookie());
    return socket;
  }

  get(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'GET' });
  }

  post(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'POST' });
  }

  put(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'PUT' });
  }

  patch(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'PATCH' });
  }

  /** `delete` is a reserved word, which is why every client calls it this. */
  del(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'DELETE' });
  }

  head(url: string | URL, init?: SessionRequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: 'HEAD' });
  }
}
