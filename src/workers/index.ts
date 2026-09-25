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
  type SessionWebSocketInit,
} from '../client/session';
import type { WebSocketConnection } from '../http/websocket';
import { verifyProfile, type Verdict } from '../fingerprint/verify';
import { zlibDecoders, type ZlibModule } from '../http/decompress';
import { zlibInflater, type InflateModule } from '../http/permessage-deflate';
import { impersonating, ticketStore } from '../tls/wasm';
import type { TicketStore } from '../../rust-tls/pkg/underfetch_tls';
import { CookieJar } from '../client/cookies';
import {
  fromBase64,
  readState,
  restoredProfile,
  SessionStateError,
  STATE_VERSION,
  toBase64,
  type SessionState,
} from './state';
import { DialError, type ByteSocket, type Dial } from '../net/socket';

/**
 * Opens a plain TCP connection. TLS is never asked of the platform: its own
 * upgrade cannot verify a certificate for a host other than the one dialled,
 * which is exactly what a tunnelled request needs.
 */
export const dial: Dial = async (hostname, port) => {
  const socket = connect({ hostname, port });
  try {
    await socket.opened;
  } catch (error) {
    throw refused(hostname, port, error);
  }
  const wrapped: ByteSocket = {
    readable: socket.readable,
    writable: socket.writable,
    close: () => socket.close(),
  };
  return wrapped;
};

/**
 * Why a connection could not be made, in words a caller can act on. A
 * deployed Worker may not open a TCP socket to Cloudflare's own addresses,
 * so a site served through Cloudflare cannot be reached from a Worker
 * without a proxy between them. `wrangler dev` does not enforce this;
 * production does.
 *
 * Production refuses it with "proxy request failed, cannot connect to the
 * specified address. It looks like you might be trying to connect to a
 * HTTP-based service — consider using fetch instead" (seen 2026-09-25). The
 * first half is also what any unreachable address gets, so only the second
 * marks the Cloudflare block, and only that is final: anything else may work
 * on another try. A socket read without awaiting `opened` fails with "Stream
 * was cancelled." instead.
 */
function refused(hostname: string, port: number, error: unknown): DialError {
  const said = error instanceof Error ? error.message : String(error);
  if (/HTTP-based service|stream was cancelled/i.test(said)) {
    return new DialError(
      `could not connect to ${hostname}:${port}: a Worker may not open TCP connections to ` +
        "Cloudflare's own IP ranges, which is where a site behind Cloudflare lives. " +
        'Reach it through a proxy (the `proxy` option).',
      true,
      { cause: error },
    );
  }
  return new DialError(`could not connect to ${hostname}:${port}: ${said}`, false, {
    cause: error,
  });
}

/**
 * The `node:zlib` a Worker carries on a recent compatibility date
 * (2026-09-21 has it, 2024-06-01 does not): brotli and zstd for bodies, and
 * raw inflate for WebSockets. Asked for through `process.getBuiltinModule`
 * rather than imported: an import of `node:zlib` on an older date stops the
 * whole Worker from starting, where this finds nothing and leaves gzip,
 * deflate and uncompressed WebSockets.
 */
const zlib = (
  globalThis as { process?: { getBuiltinModule?: (name: string) => unknown } }
).process?.getBuiltinModule?.('node:zlib') as (ZlibModule & InflateModule) | undefined;

/** Brotli and zstd, where there is a `node:zlib` to supply them. */
export const decoders = zlibDecoders(zlib);

/** permessage-deflate on a WebSocket, from the same `node:zlib`, where there is one. */
export const inflater = zlibInflater(zlib);

export interface WorkerSessionDefaults extends SessionDefaults {
  /**
   * Whose ClientHello to send: a name from `profiles`, a profile of your own,
   * or nothing at all, which sends rustls' — safe, and recognisable as rustls.
   */
  impersonate?: ProfileName | Impersonation | undefined;
  /**
   * Resume TLS sessions: a second connection to a host carries the ticket
   * the first was given, as a returning browser's does. The tickets belong
   * to this session alone. Default: true.
   */
  tlsResumption?: boolean | undefined;
}

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
  readonly #as: Impersonation | undefined;
  readonly #name: string | undefined;
  readonly #tickets: TicketStore | undefined;

  constructor({ impersonate, tlsResumption = true, ...defaults }: WorkerSessionDefaults = {}) {
    const as = typeof impersonate === 'string' ? profiles[impersonate] : impersonate;
    const tickets = tlsResumption ? ticketStore() : undefined;
    super({
      dial,
      decoders,
      inflater,
      tls: impersonating(as, tickets ?? false),
      // A browser's headers travel with its handshake. The session's own win
      // over the profile's, and a request's win over both.
      impersonate: as,
      ...defaults,
    });
    this.#as = as;
    this.#name = typeof impersonate === 'string' ? impersonate : undefined;
    this.#tickets = tickets;
  }

  /**
   * What this session has earned — which browser, its cookies, its TLS
   * tickets — as a plain object, for a Durable Object's storage or anywhere
   * else that keeps objects. `unmarshal` takes it back. Keep it as a
   * password is kept: it logs in and resumes.
   */
  state(): SessionState {
    return {
      version: STATE_VERSION,
      savedAt: Date.now(),
      impersonate: this.#as
        ? { ...(this.#name ? { name: this.#name } : {}), ja4: this.#as.expected.ja4 }
        : null,
      cookies: this.cookies?.all() ?? null,
      tickets: this.#tickets ? toBase64(this.#tickets.export()) : '',
    };
  }

  /** `state()` as JSON, for KV, D1, R2 or anything else that keeps strings. */
  marshal(): string {
    return JSON.stringify(this.state());
  }

  /**
   * A session carrying on from a saved one, in this isolate or any other.
   * The proxy, timeouts and headers are not saved and come from `options`.
   * A state saved as one browser is refused as another, and one saved with
   * a profile of your own needs that profile passed again.
   */
  static unmarshal(saved: SessionState | string, options: WorkerSessionDefaults = {}): Session {
    const state = readState(saved);
    const { impersonate } = options;
    const given = typeof impersonate === 'string' ? profiles[impersonate] : impersonate;
    if (typeof impersonate === 'string' && given === undefined) {
      throw new SessionStateError(`no built-in profile is called ${impersonate}`);
    }
    const profile = restoredProfile(
      state.impersonate,
      given,
      (name) => profiles[name as ProfileName],
    );

    let cookies = options.cookies;
    if (state.cookies !== null && cookies !== false) {
      if (!(cookies instanceof CookieJar)) cookies = new CookieJar();
      cookies.add(state.cookies);
    }
    const session = new Session({
      ...options,
      impersonate: given ?? (state.impersonate?.name as ProfileName | undefined) ?? profile,
      ...(cookies === undefined ? {} : { cookies }),
    });
    if (state.tickets !== '' && session.#tickets) {
      try {
        session.#tickets.import(fromBase64(state.tickets));
      } catch (error) {
        throw new SessionStateError(`the saved tickets could not be read: ${String(error)}`);
      }
    }
    return session;
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

export interface WorkerWebSocketInit extends SessionWebSocketInit {
  /** Whose ClientHello and headers to open it with. */
  impersonate?: ProfileName | Impersonation | undefined;
}

/**
 * Opens a WebSocket without a session. `wss:` and `https:` mean the same.
 *
 * ```ts
 * const ws = await websocket('wss://echo.example/', { impersonate: 'chrome' });
 * await ws.send('hello');
 * for await (const message of ws) console.log(message.data);
 * ```
 */
export function websocket(
  url: string | URL,
  init: WorkerWebSocketInit = {},
): Promise<WebSocketConnection> {
  const { impersonate, ...rest } = init;
  return new Session(impersonate ? { impersonate } : {}).websocket(url, rest);
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
export { SessionStateError } from './state';
export type { SessionState } from './state';
export type { Cookie } from '../client/cookies';
export type { RetryOptions } from '../client/retry';
export { profiles } from '../fingerprint/profiles';
export { FingerprintError, fromFingerprints } from '../fingerprint/custom';
export { ResourceError } from '../fingerprint/order';
export type { FetchSite, Resource } from '../fingerprint/order';
export type { FromFingerprints } from '../fingerprint/custom';
export type { Impersonation, ProfileName } from '../fingerprint/profiles';
export type { SessionDefaults, SessionRequestInit, SessionWebSocketInit } from '../client/session';
export { WebSocketConnection, WebSocketError } from '../http/websocket';
export type { WebSocketClose, WebSocketMessage } from '../http/websocket';
export { WebSocketRefused } from '../client/websocket';
export { DialError } from '../net/socket';
export type { HttpProxy, HttpsProxy, Proxy, Socks4Proxy, Socks5Proxy } from '../net/socket';
