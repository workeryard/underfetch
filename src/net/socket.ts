/**
 * The only thing this package needs from a runtime: a pair of byte streams and
 * a way to hang up. `cloudflare:sockets` provides one, and so does a pair of
 * in-memory streams in a test, which is why nothing here imports a runtime.
 *
 * There is deliberately no `startTls`: the platform's own upgrade cannot check
 * a certificate against a host other than the one dialled, which is exactly
 * what a tunnelled request needs. TLS is done in `tls.ts` instead.
 */
export interface ByteSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close(): Promise<void>;
}

/**
 * A connection that could not be opened. `permanent` says trying again will
 * not help, so a retry should not spend another connection on it.
 */
export class DialError extends Error {
  override name = 'DialError';
  constructor(
    message: string,
    readonly permanent = false,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

/** Opens a plain TCP connection. The runtime decides how. */
export type Dial = (hostname: string, port: number) => Promise<ByteSocket>;

interface ProxyAddress {
  hostname: string;
  port: number;
  /** Omitted when the proxy is open to anyone. */
  username?: string | undefined;
  password?: string | undefined;
}

/** A SOCKS5 proxy (RFC 1928), with optional username/password auth. */
export interface Socks5Proxy extends ProxyAddress {
  kind: 'socks5';
}

/**
 * A SOCKS4 proxy, speaking 4a so the target's name is resolved at the proxy.
 * SOCKS4 has no password: `username` is sent as its user ID.
 */
export interface Socks4Proxy {
  kind: 'socks4';
  hostname: string;
  port: number;
  username?: string | undefined;
}

/** A proxy that tunnels with HTTP `CONNECT`. */
export interface HttpProxy extends ProxyAddress {
  kind: 'http';
}

/**
 * The same, reached over TLS: the proxy's certificate is checked against
 * `hostname`, and the target's TLS then runs inside that one.
 */
export interface HttpsProxy extends ProxyAddress {
  kind: 'https';
}

export type Proxy = Socks5Proxy | Socks4Proxy | HttpProxy | HttpsProxy;
