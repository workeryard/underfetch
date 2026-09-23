/**
 * Sending a request out through a proxy from a Cloudflare Worker.
 *
 * `fetch()` cannot be pointed at a proxy and cannot ride a socket we opened, so
 * every layer below it is here: the SOCKS5 and HTTP CONNECT handshakes, TLS,
 * and HTTP/1.1. The runtime is kept at arm's length behind `Dial` and
 * `TlsFactory`, which is what lets all of it be tested without a network or a
 * Worker.
 */

import { deadline, until } from './abort';
import { http2Fetch, type Http2Profile } from './h2/connection';
import { http1Fetch } from './http1';
import { tlsTunnel, type TlsFactory } from './tls';
import { tunnelThrough } from './tunnel';
import type { ByteSocket, Dial, Proxy } from './socket';

export { aborted, deadline, TimeoutError, until } from './abort';
export { ByteReader, ByteWriter } from './bytes';
export { HttpConnectError, httpConnect } from './http-connect';
export { Http1Error, http1Fetch } from './http1';
export { Socks5Error, socks5Connect } from './socks5';
export { TlsError, tlsTunnel } from './tls';
export { tunnelThrough } from './tunnel';
export { DEFAULT_PROFILE, http2Fetch } from './h2/connection';
export { Http2Error } from './h2/frames';
export type { Http2Profile } from './h2/connection';
export { encodeExtensions, GREASE, profiles } from './impersonate';
export { ApiError, buildRequest, followRedirects } from './api';
export { CookieJar } from './cookies';
export type { Cookie } from './cookies';
export { withRetry } from './retry';
export type { RetryOptions } from './retry';
export type { BodyOptions, Params, RedirectOptions } from './api';
export { akamai, ja4, parseClientHello, verifyProfile, VerifyError } from './verify';
export type { ClientHello, Verdict } from './verify';
export { Session } from './session';
export type { Extension, Impersonation, ProfileName } from './impersonate';
export type { SessionDefaults, SessionOptions, SessionRequestInit } from './session';
export type { TlsFactory, TlsSession } from './tls';
export type { ByteSocket, Dial, HttpProxy, Proxy, Socks5Proxy } from './socket';

export interface ProxyFetchOptions {
  /** Opens a plain TCP connection; the runtime supplies this. */
  dial: Dial;
  /** Builds a TLS client for one connection. */
  tls: TlsFactory;
  /** Left out, the target is dialled directly — still off the `fetch` path. */
  proxy?: Proxy | undefined;
  /** Gives up after this many milliseconds, headers and body together. */
  timeoutMs?: number | undefined;
  /** Cancels the request. Given here, it replaces the request's own signal. */
  signal?: AbortSignal | undefined;
  /** How to open an HTTP/2 connection, when ALPN settles on one. */
  http2?: Http2Profile | undefined;
}

const defaultPort = (url: URL) => (url.protocol === 'http:' ? 80 : 443);

/**
 * Closes the tunnel once the answer has been read to the end, cancelled, or
 * failed. Nothing may close it earlier: the body is still streaming through it.
 */
function closingWhenDone(
  body: ReadableStream<Uint8Array>,
  socket: ByteSocket,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  const shut = () => {
    void socket.close().catch(() => undefined);
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) {
          shut();
          controller.close();
          return;
        }
        if (value) controller.enqueue(value);
      } catch (error) {
        shut();
        throw error;
      }
    },
    cancel(reason) {
      shut();
      return reader.cancel(reason);
    },
  });
}

/**
 * Performs `request` through `proxy`, so it reaches the target from the
 * proxy's address rather than Cloudflare's. The answer's body is still
 * streaming when this resolves.
 */
export async function proxyFetch(
  request: Request,
  { dial, tls, proxy, timeoutMs, signal, http2 }: ProxyFetchOptions,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TypeError(`cannot proxy ${url.protocol} requests`);
  }
  const port = url.port === '' ? defaultPort(url) : Number(url.port);
  const limit = deadline(signal ?? request.signal, timeoutMs);

  const entry = proxy ?? { hostname: url.hostname, port };
  const socket = await until(limit.signal, dial(entry.hostname, entry.port));
  // Closing the socket is what actually unblocks a read that is going nowhere,
  // so the deadline is wired to it and not only to the promise we return.
  const stop = () => void socket.close().catch(() => undefined);
  limit.signal.addEventListener('abort', stop, { once: true });

  try {
    const setup = async () => {
      const tunnel = proxy ? await tunnelThrough(socket, proxy, url.hostname, port) : socket;
      // Plain http needs no session; https gets one that checks the
      // certificate against the target's name, which the proxy never sees.
      if (url.protocol === 'http:') return http1Fetch(tunnel, request);

      const carrier = await tlsTunnel(tunnel, tls(url.hostname));
      // ALPN, not guesswork: speaking the wrong one hangs the connection.
      return carrier.protocol === 'h2'
        ? http2Fetch(carrier, request, http2)
        : http1Fetch(carrier, request);
    };

    const response = await until(limit.signal, setup());
    if (response.body === null) {
      stop();
      return response;
    }
    return new Response(closingWhenDone(response.body, socket), response);
  } catch (error) {
    stop();
    throw error;
  }
}
