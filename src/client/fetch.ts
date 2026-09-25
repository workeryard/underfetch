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
import type { Decoders } from '../http/decompress';
import { http1Fetch } from '../http/http1';
import { tunnelThrough } from '../net/proxy';
import type { ByteSocket, Dial, Proxy } from '../net/socket';
import { chaseIssuers, decodeCertificates, MAX_CERTIFICATE_BYTES } from '../tls/aia';
import { missingIssuer, unverifiableSignature } from '../tls/errors';
import { tlsTunnel, type TlsFactory, type TlsOptions, type TlsSession } from '../tls/tunnel';
import { deadline, until } from './abort';

export interface FetchOverOptions {
  /** Opens a plain TCP connection; the runtime supplies this. */
  dial: Dial;
  /** Builds a TLS client for one connection. */
  tls: TlsFactory;
  /** Left out, the target is dialled directly — still off the `fetch` path. */
  proxy?: Proxy | undefined;
  /** Gives up after this many milliseconds, headers and body together. */
  timeoutMs?: number | undefined;
  /**
   * Gives up on connecting — dialling, the proxy's handshake and TLS — after
   * this many milliseconds, so a dead proxy fails fast and a retry can try
   * again while the whole request still has time.
   */
  connectTimeoutMs?: number | undefined;
  /** Cancels the request. Given here, it replaces the request's own signal. */
  signal?: AbortSignal | undefined;
  /** How to open an HTTP/2 connection, when ALPN settles on one. */
  http2?: Http2Profile | undefined;
  /**
   * Fetch an intermediate the server left out, from the address its
   * certificate gives, as a browser does. Default: true.
   */
  completeChains?: boolean | undefined;
  /**
   * Send the request body as it arrives instead of reading it into memory
   * first: chunked on HTTP/1.1, frame by frame on HTTP/2. For uploads too
   * large to hold. Default: false.
   */
  streamBody?: boolean | undefined;
  /**
   * Decoders beyond gzip and deflate — brotli and zstd, where the runtime has
   * them. The Workers adapter fills this in.
   */
  decoders?: Decoders | undefined;
}

const defaultPort = (url: URL) => (url.protocol === 'http:' || url.protocol === 'ws:' ? 80 : 443);

/**
 * Closes the tunnel once the answer has been read to the end, cancelled, or
 * failed. Nothing may close it earlier: the body is still streaming through it.
 */
function closingWhenDone(
  body: ReadableStream<Uint8Array>,
  socket: ByteSocket,
  signal: AbortSignal,
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
        // The deadline closes the socket to stop the read, and the read then
        // fails as a closed socket; the caller should hear why it was closed.
        throw signal.aborted ? (signal.reason as Error) : error;
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
 * Performs `request` over a connection of our own: `dial` opens the socket,
 * `tls` secures it, and `proxy`, when given, is where it leaves from — so it
 * reaches the target from the proxy's address rather than Cloudflare's.
 * One request, one connection; `Session` is what keeps settings between
 * them. The answer's body is still streaming when this resolves.
 */
export async function fetchOver(request: Request, options: FetchOverOptions): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TypeError(`cannot proxy ${url.protocol} requests`);
  }
  const limit = deadline(options.signal ?? request.signal, options.timeoutMs);
  // Only while the request can be sent again: a handshake fails before any
  // body is read, but a caller's stream is not ours to assume unread.
  return remedied(
    options,
    limit.signal,
    (tls) => attempt(request, url, options, tls, limit.signal),
    () => !request.bodyUsed,
  );
}

/**
 * Runs `once` with a TLS factory, and again when it fails in a way a second
 * connection can fix. Each failure has one remedy, tried once, so this ends
 * after three attempts at most. `again` says whether trying again is still
 * possible at all.
 */
export async function remedied<T>(
  options: Pick<FetchOverOptions, 'dial' | 'tls' | 'proxy' | 'completeChains' | 'http2'>,
  signal: AbortSignal,
  once: (tls: TlsFactory) => Promise<T>,
  again: () => boolean = () => true,
): Promise<T> {
  const remedies: TlsOptions = {};
  for (;;) {
    let last: TlsSession | undefined;
    const recording: TlsFactory = (hostname, alpn) =>
      (last = options.tls(hostname, alpn, { ...remedies }));
    try {
      return await once(recording);
    } catch (error) {
      if (!again()) throw error;
      if (unverifiableSignature(error) && !remedies.verifiableSignatures) {
        remedies.verifiableSignatures = true;
        continue;
      }
      if (
        missingIssuer(error) &&
        options.completeChains !== false &&
        remedies.intermediates === undefined
      ) {
        const found = await completeChain(last, options, signal);
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
  options: Pick<FetchOverOptions, 'dial' | 'tls' | 'proxy' | 'http2'>,
  signal: AbortSignal,
): Promise<Uint8Array[]> {
  const presented = session?.presentedChain?.();
  if (presented === undefined) return [];
  const fetchCertificate = async (address: string) => {
    const response = await fetchOver(new Request(address), {
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

/** A connection ready for HTTP: through the proxy, and through TLS for https. */
export interface Carrier {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /** What ALPN settled on; undefined for plain http. */
  protocol: string | undefined;
  /** The TCP socket underneath, which is what closing means. */
  socket: ByteSocket;
  /** Stops `signal` from closing the socket, for a connection that outlives it. */
  detach: () => void;
}

/**
 * Dials, tunnels through the proxy, and for https completes a TLS handshake
 * offering `alpn`. `signal` closes the socket, which is what actually
 * unblocks a read that is going nowhere; until `detach`, it stays wired.
 */
export async function openCarrier(
  url: URL,
  {
    dial,
    proxy,
    tls: proxyTls,
    connectTimeoutMs,
  }: Pick<FetchOverOptions, 'dial' | 'proxy' | 'tls' | 'connectTimeoutMs'>,
  tls: TlsFactory,
  signal: AbortSignal,
  alpn?: string,
): Promise<Carrier> {
  const port = url.port === '' ? defaultPort(url) : Number(url.port);
  const entry = proxy ?? { hostname: url.hostname, port };
  // Connecting has a deadline of its own, spent once the connection is up;
  // `signal` goes on holding the socket for as long as it is used.
  const connecting = deadline(signal, connectTimeoutMs, 'connecting').signal;
  const socket = await until(connecting, dial(entry.hostname, entry.port));
  const stop = () => void socket.close().catch(() => undefined);
  signal.addEventListener('abort', stop, { once: true });
  connecting.addEventListener('abort', stop, { once: true });
  const detach = () => signal.removeEventListener('abort', stop);

  try {
    const setup = async (): Promise<Carrier> => {
      const tunnel = proxy
        ? await tunnelThrough(await toProxy(socket, proxy, proxyTls), proxy, url.hostname, port)
        : socket;
      // Plain http needs no session; https gets one that checks the
      // certificate against the target's name, which the proxy never sees.
      if (url.protocol === 'http:' || url.protocol === 'ws:') {
        return { ...tunnel, protocol: undefined, socket, detach };
      }
      const carrier = await tlsTunnel(tunnel, tls(url.hostname, alpn));
      return { ...carrier, socket, detach };
    };
    return await until(connecting, setup());
  } catch (error) {
    stop();
    throw error;
  } finally {
    connecting.removeEventListener('abort', stop);
  }
}

/**
 * The connection the proxy's own handshake runs over: the socket itself, or
 * for an HTTPS proxy a TLS session to it, checked against the proxy's name.
 * The target's TLS then runs inside this one. It is not the target's
 * handshake, so none of the target's remedies apply to it.
 */
async function toProxy(socket: ByteSocket, proxy: Proxy, tls: TlsFactory): Promise<ByteSocket> {
  if (proxy.kind !== 'https') return socket;
  const secured = await tlsTunnel(socket, tls(proxy.hostname, 'http/1.1'));
  return { readable: secured.readable, writable: secured.writable, close: () => socket.close() };
}

/** One connection: dial, tunnel, TLS, and the request over whichever HTTP. */
async function attempt(
  request: Request,
  url: URL,
  options: FetchOverOptions,
  tls: TlsFactory,
  signal: AbortSignal,
): Promise<Response> {
  const { http2, streamBody, decoders } = options;
  const carrier = await openCarrier(url, options, tls, signal);
  const stop = () => void carrier.socket.close().catch(() => undefined);

  try {
    // ALPN, not guesswork: speaking the wrong one hangs the connection.
    const exchange = () =>
      carrier.protocol === 'h2'
        ? http2Fetch(carrier, request, http2, { streamBody, decoders })
        : http1Fetch(carrier, request, { streamBody, decoders });
    const response = await until(signal, exchange());
    if (response.body === null) {
      stop();
      return response;
    }
    return new Response(closingWhenDone(response.body, carrier.socket, signal), response);
  } catch (error) {
    stop();
    throw error;
  }
}
