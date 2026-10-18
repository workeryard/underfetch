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
import { FingerprintError, withFingerprints, type Fingerprints } from '../fingerprint/custom';
import {
  fromBase64,
  identityOf,
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
   * A JA3 string to send instead of the profile's own, as tls.peet.ws shows
   * it for a browser. What it does not say — signature algorithms, headers,
   * extension bodies — still comes from `impersonate`, which it needs.
   */
  ja3?: string | undefined;
  /** An Akamai HTTP/2 string to send instead of the profile's own. */
  akamai?: string | undefined;
  /**
   * With `ja3`: shuffle its extensions on every connection, as Chrome does,
   * rather than keep the one order a JA3 string records. Default: false.
   */
  shuffle?: boolean | undefined;
  /**
   * Resume TLS sessions: a second connection to a host carries the ticket
   * the first was given, as a returning browser's does. The tickets belong
   * to this session alone. Default: true.
   */
  tlsResumption?: boolean | undefined;
  /**
   * A Worker may not open a socket to Cloudflare's own addresses, so a site
   * behind Cloudflare cannot be reached without a proxy. `'error'`, the
   * default, fails with a `DialError` saying so. `'fetch'` sends such a
   * request through the Worker's own fetch() instead: it arrives, but with
   * Cloudflare's TLS rather than the profile's and Cloudflare's headers
   * added, and its answer carries `x-underfetch-via: fallback`. WebSockets
   * are not covered.
   */
  onCloudflare?: 'error' | 'fetch' | undefined;
}

/**
 * The Worker's own fetch, for `onCloudflare: 'fetch'`. It undoes gzip and
 * brotli itself yet leaves `content-encoding` on the answer (seen on
 * 2026-09-25), which would send a caller decoding twice; so the header goes,
 * and `content-length` with it, since it counts the encoded bytes. Redirects
 * stay the session's to follow, hop by hop, cookies and all.
 */
async function platformFetch(request: Request): Promise<Response> {
  const response = await fetch(request, { redirect: 'manual' });
  if (!response.headers.has('content-encoding')) return response;
  const headers = new Headers(response.headers);
  headers.delete('content-encoding');
  headers.delete('content-length');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
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
/** The profile `impersonate`, `ja3` and `akamai` describe together. */
function profileFor(
  impersonate: ProfileName | Impersonation | undefined,
  input: Fingerprints | undefined,
): Impersonation | undefined {
  const base = typeof impersonate === 'string' ? profiles[impersonate] : impersonate;
  if (typeof impersonate === 'string' && base === undefined) {
    throw new FingerprintError(`no built-in profile is called ${impersonate}`);
  }
  if (input === undefined) return base;
  if (base === undefined) {
    throw new FingerprintError(
      'ja3 and akamai change a profile, so they need one to start from: say `impersonate` too',
    );
  }
  return withFingerprints(base, input);
}

/** The strings given, or nothing when none were. */
function inputOf({ ja3, akamai, shuffle }: WorkerSessionDefaults): Fingerprints | undefined {
  if (ja3 === undefined && akamai === undefined) return undefined;
  return {
    ...(ja3 === undefined ? {} : { ja3 }),
    ...(akamai === undefined ? {} : { akamai }),
    ...(shuffle ? { shuffle } : {}),
  };
}

export class Session extends PlainSession {
  readonly #as: Impersonation | undefined;
  readonly #name: string | undefined;
  readonly #input: Fingerprints | undefined;
  readonly #tickets: TicketStore | undefined;

  constructor({
    impersonate,
    ja3,
    akamai,
    shuffle,
    tlsResumption = true,
    onCloudflare = 'error',
    ...defaults
  }: WorkerSessionDefaults = {}) {
    const input = inputOf({ ja3, akamai, shuffle });
    const as = profileFor(impersonate, input);
    const tickets = tlsResumption ? ticketStore() : undefined;
    super({
      dial,
      decoders,
      inflater,
      tls: impersonating(as, tickets ?? false),
      // A browser's headers travel with its handshake. The session's own win
      // over the profile's, and a request's win over both.
      impersonate: as,
      ...(onCloudflare === 'fetch' ? { fallback: platformFetch } : {}),
      ...defaults,
    });
    this.#as = as;
    this.#name = typeof impersonate === 'string' ? impersonate : undefined;
    this.#input = input;
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
      impersonate: this.#as ? identityOf(this.#as, this.#name, this.#input) : null,
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
   * The profile comes back by itself, `ja3` and `akamai` included, unless
   * it was one of your own; either way a state saved as one browser is
   * refused as another.
   */
  static unmarshal(saved: SessionState | string, options: WorkerSessionDefaults = {}): Session {
    const state = readState(saved);
    const givenInput = inputOf(options);
    const given =
      options.impersonate === undefined && givenInput === undefined
        ? undefined
        : profileFor(options.impersonate, givenInput);
    restoredProfile(state.impersonate, given, (name) => profiles[name as ProfileName]);

    let cookies = options.cookies;
    if (state.cookies !== null && cookies !== false) {
      if (!(cookies instanceof CookieJar)) cookies = new CookieJar();
      cookies.add(state.cookies);
    }
    // Given nothing, it is rebuilt from what the state recorded; the check
    // above has made sure that is the same browser.
    const identity = state.impersonate;
    const session = new Session({
      ...options,
      ...(given === undefined && identity !== null
        ? { impersonate: identity.name as ProfileName, ...identity.input }
        : {}),
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
 * hold a `Session` instead — it keeps the connections open between them, and
 * the proxy, the profile and the headers in one place.
 */
export function request(
  method: string,
  input: string | URL,
  init?: WorkerRequestInit,
): Promise<Response> {
  const { impersonate, ja3, akamai, shuffle, ...rest } = init ?? {};
  // Nothing else will ride its connection, so it closes with the answer.
  return new Session({ impersonate, ja3, akamai, shuffle, keepAlive: false }).fetch(input, {
    ...rest,
    method,
  });
}

export interface WorkerRequestInit
  extends
    SessionRequestInit,
    Pick<WorkerSessionDefaults, 'impersonate' | 'ja3' | 'akamai' | 'shuffle'> {}

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
export { GREASE, profiles } from '../fingerprint/profiles';
export { FingerprintError } from '../fingerprint/custom';
export { ResourceError } from '../fingerprint/order';
export type { FetchSite, Resource } from '../fingerprint/order';
export type { Impersonation, ProfileName } from '../fingerprint/profiles';
export type { SessionDefaults, SessionRequestInit, SessionWebSocketInit } from '../client/session';
export { WebSocketConnection, WebSocketError } from '../http/websocket';
export type { WebSocketClose, WebSocketMessage } from '../http/websocket';
export { WebSocketRefused } from '../client/websocket';
export { DialError } from '../net/socket';
export type { HttpProxy, HttpsProxy, Proxy, Socks4Proxy, Socks5Proxy } from '../net/socket';
