/**
 * The Cloudflare Workers adapter: the one place that names the runtime.
 *
 * Everything under `src/` above this folder is plain TypeScript that takes a
 * `Dial` and a `TlsFactory`. Here they are filled in — `cloudflare:sockets` for
 * the connection, the WebAssembly rustls for TLS — so the common case is
 * `new Session()` and nothing else.
 */

import { connect } from 'cloudflare:sockets';
import { profiles, type Impersonation, type ProfileName } from '../impersonate';
import { Session as PlainSession, type SessionDefaults, type SessionRequestInit } from '../session';
import { verifyProfile, type Verdict } from '../verify';
import { impersonating } from '../wasm-tls';
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
export interface WorkerSessionDefaults extends SessionDefaults {
  /**
   * Whose ClientHello to send: a name from `profiles`, a profile of your own,
   * or nothing at all, which sends rustls' — safe, and recognisable as rustls.
   */
  impersonate?: ProfileName | Impersonation | undefined;
}

export class Session extends PlainSession {
  constructor({ impersonate, ...defaults }: WorkerSessionDefaults = {}) {
    const as = typeof impersonate === 'string' ? profiles[impersonate] : impersonate;
    super({
      dial,
      tls: impersonating(as),
      ...(as ? { http2: as.http2 } : {}),
      // A browser's ALPN travels with its fingerprint, so a profile sets the
      // headers' protocol too unless the caller said otherwise.
      ...defaults,
    });
  }
}

/** One request, for when a session would only be built to be thrown away. */
export function socketFetch(
  input: string | URL | Request,
  init?: SessionRequestInit,
): Promise<Response> {
  return new Session().fetch(input, init);
}

/**
 * Checks every built-in profile against the fingerprints it claims, using a
 * real ClientHello from the TLS module. No network, no third party.
 */
export async function selfTest(): Promise<Verdict[]> {
  const out: Verdict[] = [];
  for (const [name, profile] of Object.entries(profiles)) {
    const session = impersonating(profile)('example.com');
    out.push(await verifyProfile(name, profile, session.outgoing()));
    session.close();
  }
  return out;
}

export { akamai, ja4, parseClientHello, verifyProfile } from '../verify';
export type { ClientHello, Verdict } from '../verify';
export { impersonating, wasmTls } from '../wasm-tls';
export { profiles } from '../impersonate';
export type { Impersonation, ProfileName } from '../impersonate';
export type { SessionDefaults, SessionRequestInit } from '../session';
export type { HttpProxy, Proxy, Socks5Proxy } from '../socket';
