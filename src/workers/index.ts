/**
 * The Cloudflare Workers adapter: the one place that names the runtime.
 *
 * Everything under `src/` above this folder is plain TypeScript that takes a
 * `Dial` and a `TlsFactory`. Here they are filled in — `cloudflare:sockets` for
 * the connection, the WebAssembly rustls for TLS — so the common case is
 * `new Session()` and nothing else.
 */

import { connect } from 'cloudflare:sockets';
import { profiles, type Impersonation, type ProfileName } from '../fingerprint/profiles';
import {
  Session as PlainSession,
  type SessionDefaults,
  type SessionRequestInit,
} from '../client/session';
import { verifyProfile, type Verdict } from '../fingerprint/verify';
import { impersonating } from '../tls/wasm';
import type { ByteSocket, Dial } from '../net/socket';

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
/** The profile's headers, with anything the session set taking precedence. */
function browserHeaders(as: Impersonation, own: HeadersInit | undefined): Headers {
  const headers = new Headers(as.headers as [string, string][]);
  if (own !== undefined) {
    for (const [name, value] of new Headers(own)) headers.set(name, value);
  }
  return headers;
}

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
      ...defaults,
      // A browser's headers travel with its handshake. The session's own win
      // over the profile's, and a request's win over both.
      ...(as ? { headers: browserHeaders(as, defaults.headers) } : {}),
    });
  }
}

/**
 * One request, for when a session would only be built to be thrown away.
 *
 * Each of these opens its own connection, so a caller making several should
 * hold a `Session` instead — it keeps the proxy, the profile and the headers
 * in one place rather than repeating them.
 */
export function request(
  method: string,
  input: string | URL,
  init?: WorkerRequestInit,
): Promise<Response> {
  const { impersonate, ...rest } = init ?? {};
  return new Session(impersonate ? { impersonate } : {}).fetch(input, { ...rest, method });
}

export interface WorkerRequestInit extends SessionRequestInit {
  /** Whose ClientHello to send for this one request. */
  impersonate?: ProfileName | Impersonation | undefined;
}

export const get = (url: string | URL, init?: WorkerRequestInit) => request('GET', url, init);
export const post = (url: string | URL, init?: WorkerRequestInit) => request('POST', url, init);
export const put = (url: string | URL, init?: WorkerRequestInit) => request('PUT', url, init);
export const patch = (url: string | URL, init?: WorkerRequestInit) => request('PATCH', url, init);
/** `delete` is a reserved word, which is why every client calls it this. */
export const del = (url: string | URL, init?: WorkerRequestInit) => request('DELETE', url, init);
export const head = (url: string | URL, init?: WorkerRequestInit) => request('HEAD', url, init);

/** The same as `get`, kept for callers that read better this way. */
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

export { akamai, ja3, ja4, parseClientHello, verifyProfile } from '../fingerprint/verify';
export type { ClientHello, Verdict } from '../fingerprint/verify';
export { impersonating, wasmTls } from '../tls/wasm';
export { CookieJar } from '../client/cookies';
export type { Cookie } from '../client/cookies';
export type { RetryOptions } from '../client/retry';
export { profiles } from '../fingerprint/profiles';
export { FingerprintError, fromFingerprints } from '../fingerprint/custom';
export type { FromFingerprints } from '../fingerprint/custom';
export type { Impersonation, ProfileName } from '../fingerprint/profiles';
export type { SessionDefaults, SessionRequestInit } from '../client/session';
export type { HttpProxy, Proxy, Socks5Proxy } from '../net/socket';
