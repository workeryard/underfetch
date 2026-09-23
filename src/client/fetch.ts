/**
 * One request, from dialling to the first byte of the answer.
 *
 * `fetch()` cannot be pointed at a proxy and cannot ride a socket we opened, so
 * every layer below it is walked here: the proxy handshake, TLS, and HTTP/1.1
 * or HTTP/2 as ALPN decides. The runtime is kept at arm's length behind `Dial`
 * and `TlsFactory`, which is what lets all of it be tested without a network
 * or a Worker.
 */

import { http2Fetch, type Http2Profile } from '../http/h2/connection';
import { http1Fetch } from '../http/http1';
import { tunnelThrough } from '../net/proxy';
import type { ByteSocket, Dial, Proxy } from '../net/socket';
import { chaseIssuers, decodeCertificates, MAX_CERTIFICATE_BYTES } from '../tls/aia';
import { missingIssuer, unverifiableSignature } from '../tls/errors';
import { tlsTunnel, type TlsFactory, type TlsOptions, type TlsSession } from '../tls/tunnel';
import { deadline, until } from './abort';

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
  /**
   * Fetch an intermediate the server left out, from the address its
   * certificate gives, as a browser does. Default: true.
   */
  completeChains?: boolean | undefined;
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
 * Reads a body of at most `limit` bytes; anything larger comes back empty,
 * since a certificate that size is not one.
 */
async function capped(response: Response, limit: number): Promise<Uint8Array> {
  const reader = response.body?.getReader();
  if (reader === undefined) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return new Uint8Array(0);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.byteLength;
  }
  return out;
}

/**
 * Performs `request` through `proxy`, so it reaches the target from the
 * proxy's address rather than Cloudflare's. The answer's body is still
 * streaming when this resolves.
 */
export async function proxyFetch(request: Request, options: ProxyFetchOptions): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TypeError(`cannot proxy ${url.protocol} requests`);
  }
  const limit = deadline(options.signal ?? request.signal, options.timeoutMs);

  // Each failure a second connection can fix has one remedy, tried once, so
  // this ends after three attempts at most.
  const remedies: TlsOptions = {};
  for (;;) {
    let last: TlsSession | undefined;
    const recording: TlsFactory = (hostname, alpn) =>
      (last = options.tls(hostname, alpn, { ...remedies }));
    try {
      return await attempt(request, url, options, recording, limit.signal);
    } catch (error) {
      // Only while the request can be sent again: a handshake fails before
      // any body is read, but a caller's stream is not ours to assume unread.
      if (request.bodyUsed) throw error;
      if (unverifiableSignature(error) && !remedies.verifiableSignatures) {
        remedies.verifiableSignatures = true;
        continue;
      }
      if (
        missingIssuer(error) &&
        options.completeChains !== false &&
        remedies.intermediates === undefined
      ) {
        const found = await completeChain(last, options, limit.signal);
        if (found.length > 0) {
          remedies.intermediates = found;
          continue;
        }
      }
      throw error;
    }
  }
}

/**
 * Fetches the issuers a failed handshake's chain was missing, over the same
 * route the request took. Returns nothing when there is nothing to fetch.
 */
async function completeChain(
  session: TlsSession | undefined,
  options: ProxyFetchOptions,
  signal: AbortSignal,
): Promise<Uint8Array[]> {
  const presented = session?.presentedChain?.();
  if (presented === undefined) return [];
  const fetchCertificate = async (address: string) => {
    const response = await proxyFetch(new Request(address), {
      ...options,
      signal,
      completeChains: false,
    });
    if (!response.ok) {
      await response.body?.cancel();
      return new Uint8Array(0);
    }
    return capped(response, MAX_CERTIFICATE_BYTES);
  };
  return chaseIssuers(decodeCertificates(presented), fetchCertificate).catch(() => []);
}

/** One connection: dial, tunnel, TLS, and the request over whichever HTTP. */
async function attempt(
  request: Request,
  url: URL,
  { dial, proxy, http2 }: ProxyFetchOptions,
  tls: TlsFactory,
  signal: AbortSignal,
): Promise<Response> {
  const port = url.port === '' ? defaultPort(url) : Number(url.port);
  const entry = proxy ?? { hostname: url.hostname, port };
  const socket = await until(signal, dial(entry.hostname, entry.port));
  // Closing the socket is what actually unblocks a read that is going nowhere,
  // so the deadline is wired to it and not only to the promise we return.
  const stop = () => void socket.close().catch(() => undefined);
  signal.addEventListener('abort', stop, { once: true });

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

    const response = await until(signal, setup());
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
