/**
 * Connections kept for the next request to the same place, as a browser
 * keeps them.
 *
 * A browser opens one HTTP/2 connection to an origin and sends everything
 * after down it, and keeps an HTTP/1.1 connection open for the next request
 * once an answer is read. A client that dials afresh for each request looks
 * like neither, pays a handshake every time, and in a Worker spends one of
 * the few connections an invocation may open.
 *
 * What a connection is keyed by is where it goes and how: the scheme, host
 * and port, and the proxy it leaves through. The TLS profile is the
 * session's, the same for all of them.
 */

import { Http2Connection, type Http2Profile } from '../http/h2/connection';
import type { Decoders } from '../http/decompress';
import { Http1Connection } from '../http/http1';
import type { Proxy } from '../net/socket';
import { until } from './abort';
import type { Carrier } from './fetch';

export interface PoolOptions {
  /**
   * Keep connections open for the next request. Left false, each closes once
   * its answer has been read, which is what a single `fetchOver` wants.
   */
  keepAlive?: boolean | undefined;
  /** Idle HTTP/1.1 connections kept per origin, as Chrome keeps six. Default: 6. */
  maxIdle?: number | undefined;
  /**
   * How long an idle HTTP/1.1 connection is trusted to still be open. A
   * server that hangs up sooner costs a resend, not an error. Default: 60 s.
   */
  idleMs?: number | undefined;
}

export interface ExchangeOptions {
  /** How to open an HTTP/2 connection, and this request's priority on it. */
  http2?: Http2Profile | undefined;
  streamBody?: boolean | undefined;
  decoders?: Decoders | undefined;
  headerOrder?: readonly string[] | undefined;
  /** Gives up on this request; a shared connection outlives it. */
  signal: AbortSignal;
}

interface Idle {
  connection: Http1Connection;
  carrier: Carrier;
  since: number;
}

type Opened =
  | { kind: 'h2'; connection: Http2Connection }
  | { kind: 'h1'; connection: Http1Connection; carrier: Carrier; key: string };

/** Where a connection goes, and through what. */
export function poolKey(url: URL, port: number, proxy: Proxy | undefined): string {
  const via =
    proxy === undefined
      ? 'direct'
      : `${proxy.kind}://${proxy.username ?? ''}:${'password' in proxy ? (proxy.password ?? '') : ''}@${proxy.hostname}:${proxy.port}`;
  return `${url.protocol}//${url.hostname}:${port} via ${via}`;
}

/** Whether `error` says the request was never acted on, so may go again. */
const unprocessed = (error: unknown) =>
  (error as { unprocessed?: unknown } | null)?.unprocessed === true;

/** Fails a body's read with why the request was given up, not with what that broke. */
function explained(body: ReadableStream<Uint8Array>, signal: AbortSignal) {
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { value, done } = await reader.read();
        if (done) controller.close();
        else controller.enqueue(value);
      } catch (error) {
        // The deadline closes the socket to stop the read, and the read then
        // fails as a closed socket; the caller should hear why it was closed.
        throw signal.aborted ? (signal.reason as Error) : error;
      }
    },
    cancel: (reason) => reader.cancel(reason),
  });
}

export class ConnectionPool {
  readonly #keepAlive: boolean;
  readonly #maxIdle: number;
  readonly #idleMs: number;
  readonly #h2 = new Map<string, Http2Connection[]>();
  readonly #idle = new Map<string, Idle[]>();
  /** HTTP/1.1 connections carrying an answer, so `close()` reaches them too. */
  readonly #busy = new Set<Carrier>();
  /** Connections being opened, which a request for the same place may wait on. */
  readonly #opening = new Map<string, Promise<Opened>>();
  /** What ALPN settled on the last time each place was reached. */
  readonly #protocols = new Map<string, string>();

  constructor({ keepAlive = true, maxIdle = 6, idleMs = 60_000 }: PoolOptions = {}) {
    this.#keepAlive = keepAlive;
    this.#maxIdle = maxIdle;
    this.#idleMs = idleMs;
  }

  /**
   * Sends `request` to the place `key` names: on a connection already open
   * there when one is free, else on one `open` makes. A kept connection the
   * server had already let go of costs a second try on a new one, which is
   * safe because nothing was acted on.
   */
  async exchange(
    key: string,
    open: () => Promise<Carrier>,
    request: Request,
    options: ExchangeOptions,
  ): Promise<Response> {
    let kept = this.#take(key);
    // A connection still being opened may turn out to be HTTP/2, which takes
    // this request too; a browser waits for it rather than dial again. Only a
    // place known to speak HTTP/1.1 is not worth the wait.
    if (kept === undefined && this.#protocols.get(key) !== 'http/1.1') {
      const pending = this.#opening.get(key);
      if (pending !== undefined) {
        await until(options.signal, pending).catch(() => undefined);
        options.signal.throwIfAborted();
        kept = this.#take(key);
      }
    }

    if (kept !== undefined) {
      // A body read out on the first try is needed again for a second.
      const spare = request.body === null ? request : options.streamBody ? null : request.clone();
      try {
        return await this.#on(kept, request, options);
      } catch (error) {
        if (!unprocessed(error) || spare === null || options.signal.aborted) throw error;
        request = spare;
      }
    }
    return this.#on(await this.#open(key, open, options.http2), request, options);
  }

  /** Closes every connection it holds. It can still be used after. */
  close(): void {
    for (const list of this.#h2.values()) for (const connection of list) connection.close();
    const idle = [...this.#idle.values()].flat().map(({ carrier }) => carrier);
    for (const carrier of [...idle, ...this.#busy]) {
      void carrier.socket.close().catch(() => undefined);
    }
    this.#h2.clear();
    this.#idle.clear();
    this.#busy.clear();
  }

  /** A connection open to `key` that can take a request now, if there is one. */
  #take(key: string): Opened | undefined {
    const shared = this.#h2.get(key);
    if (shared !== undefined) {
      const alive = shared.filter((connection) => connection.alive);
      if (alive.length === 0) this.#h2.delete(key);
      else this.#h2.set(key, alive);
      const free = alive.find((connection) => connection.available);
      if (free !== undefined) return { kind: 'h2', connection: free };
    }
    const idle = this.#idle.get(key);
    while (idle !== undefined && idle.length > 0) {
      const { connection, carrier, since } = idle.pop()!;
      if (Date.now() - since <= this.#idleMs) return { kind: 'h1', connection, carrier, key };
      void carrier.socket.close().catch(() => undefined);
    }
    return undefined;
  }

  async #open(
    key: string,
    open: () => Promise<Carrier>,
    profile: Http2Profile | undefined,
  ): Promise<Opened> {
    const opening = (async (): Promise<Opened> => {
      const carrier = await open();
      // From here the socket is the connection's, and one request giving up
      // must not close it under the others.
      carrier.detach();
      // Plain http has no ALPN, and is HTTP/1.1 all the same.
      this.#protocols.set(key, carrier.protocol ?? 'http/1.1');
      if (carrier.protocol !== 'h2') {
        return { kind: 'h1', connection: new Http1Connection(carrier), carrier, key };
      }
      const connection: Http2Connection = new Http2Connection(carrier, profile, {
        close: () => void carrier.socket.close().catch(() => undefined),
        onIdle: () => {
          if (!this.#keepAlive) connection.close();
        },
      });
      if (this.#keepAlive) this.#h2.set(key, [...(this.#h2.get(key) ?? []), connection]);
      return { kind: 'h2', connection };
    })();
    this.#opening.set(key, opening);
    try {
      return await opening;
    } finally {
      if (this.#opening.get(key) === opening) this.#opening.delete(key);
    }
  }

  async #on(opened: Opened, request: Request, options: ExchangeOptions): Promise<Response> {
    const { signal, streamBody, decoders, headerOrder } = options;
    if (opened.kind === 'h2') {
      return opened.connection.request(request, {
        profile: options.http2,
        streamBody,
        decoders,
        headerOrder,
        signal,
      });
    }

    // HTTP/1.1 cannot drop one request and keep the connection: giving up
    // means hanging up, which is also what unblocks a read going nowhere.
    const { connection, carrier, key } = opened;
    const stop = () => void carrier.socket.close().catch(() => undefined);
    signal.addEventListener('abort', stop, { once: true });
    this.#busy.add(carrier);
    const unlisten = () => {
      signal.removeEventListener('abort', stop);
      return this.#busy.delete(carrier);
    };
    try {
      signal.throwIfAborted();
      const { response, done } = await until(
        signal,
        connection.exchange(request, { streamBody, decoders, headerOrder }),
      );
      void done.then((reusable) => {
        // Not still held: `close()` has let it go meanwhile.
        const held = unlisten();
        if (reusable && held && !signal.aborted) this.#release(key, carrier, connection);
        else stop();
      });
      if (response.body === null) return response;
      return new Response(explained(response.body, signal), response);
    } catch (error) {
      unlisten();
      stop();
      throw error;
    }
  }

  /** Puts an HTTP/1.1 connection whose answer was read back for the next. */
  #release(key: string, carrier: Carrier, connection: Http1Connection): void {
    const idle = this.#idle.get(key) ?? [];
    if (!this.#keepAlive || idle.length >= this.#maxIdle) {
      void carrier.socket.close().catch(() => undefined);
      return;
    }
    idle.push({ connection, carrier, since: Date.now() });
    this.#idle.set(key, idle);
  }
}
