/**
 * The Cloudflare Workers adapter: the one place that names the runtime.
 *
 * Everything under `src/` above this folder is plain TypeScript that takes a
 * `Dial` and a `TlsFactory`. Here they are filled in — `cloudflare:sockets` for
 * the connection, the WebAssembly rustls for TLS — so the common case is
 * `new Session()` and nothing else.
 */

import { connect } from 'cloudflare:sockets';
import { Session as PlainSession, type SessionDefaults, type SessionRequestInit } from '../session';
import { wasmTls } from '../wasm-tls';
import type { ByteSocket, Dial } from '../socket';

/**
 * Opens a plain TCP connection. TLS is never asked of the platform: its own
 * upgrade cannot verify a certificate for a host other than the one dialled,
 * which is exactly what a tunnelled request needs.
 */
export const dial: Dial = (hostname, port) => {
  const socket = connect({ hostname, port });
  const wrapped: ByteSocket = {
    readable: socket.readable,
    writable: socket.writable,
    close: () => socket.close(),
  };
  return Promise.resolve(wrapped);
};

/**
 * A client that leaves through a proxy, or straight off a socket when given
 * none — either way without the `cf-*` headers `fetch` adds.
 *
 * ```ts
 * const session = new Session({ proxy: { kind: 'socks5', hostname, port } });
 * const response = await session.fetch('https://api.example.com/v1/models');
 * ```
 */
export class Session extends PlainSession {
  constructor(defaults: SessionDefaults = {}) {
    super({ dial, tls: wasmTls, ...defaults });
  }
}

/** One request, for when a session would only be built to be thrown away. */
export function socketFetch(
  input: string | URL | Request,
  init?: SessionRequestInit,
): Promise<Response> {
  return new Session().fetch(input, init);
}

export { wasmTls } from '../wasm-tls';
export type { SessionDefaults, SessionRequestInit } from '../session';
export type { HttpProxy, Proxy, Socks5Proxy } from '../socket';
