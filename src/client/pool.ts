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
import { timed, type Phases } from './timing';

export interface PoolOptions {
  /**
   * Keep connections open for the next request. Left false, each closes once
   * its answer has been read, which is what a single `fetchOver` wants.
   */
  keepAlive?: boolean | undefined;
  /** Idle HTTP/1.1 connections kept per origin, as Chrome keeps six. Default: 6. */
  maxIdle?: number | undefined;
  /**
   * How long a connection with nothing to carry is kept, HTTP/1.1 or
   * HTTP/2, before it is closed. A server that hangs up sooner costs a
   * resend, not an error. Default: 60 s.
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
  /** When the request began, which its timing counts from. */
  start: number;
}

interface Idle {
  connection: Http1Connection;
  carrier: Carrier;
  since: number;
  timer: Timer;
}

type Timer = ReturnType<typeof setTimeout>;

/**
 * Runs `fire` after `ms`, without keeping a Node process alive for it: an
 * idle pool is no reason to stay up. Workers' timers have no `unref`.
 */
function later(ms: number, fire: () => void): Timer {
  const timer = setTimeout(fire, ms);
  (timer as { unref?: () => void }).unref?.();
  return timer;
}

/** Workers' clearTimeout takes no undefined, where Node's and the DOM's do. */
function cancel(timer: Timer | undefined): void {
  if (timer !== undefined) clearTimeout(timer);
}

/** Closing a socket once, however many paths ask for it. */
const closing = new WeakMap<Carrier, Promise<void>>();
function shut(carrier: Carrier): Promise<void> {
  let closed = closing.get(carrier);
  if (closed === undefined) {
    closed = carrier.socket.close().catch(() => undefined);
    closing.set(carrier, closed);
  }
  return closed;
}

/** A connection to send on, and what opening it cost when it was just opened. */
type Opened = (
  | { kind: 'h2'; connection: Http2Connection }
  | { kind: 'h1'; connection: Http1Connection; carrier: Carrier; key: string }
) & { phases?: Phases | undefined };

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
  return new ReadableStream<Uint8Array>(
    {
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
    },
    // Read only when asked: a wrapper reading ahead would drain the socket
    // before the caller wants the bytes, and undo HTTP/2's flow control.
    { highWaterMark: 0 },
  );
}

export class ConnectionPool {
  readonly #keepAlive: boolean;
  readonly #maxIdle: number;
  readonly #idleMs: number;
  readonly #h2 = new Map<string, Http2Connection[]>();
  /** Each HTTP/2 connection's socket, and its timer while it carries nothing. */
  readonly #h2Carriers = new Map<Http2Connection, Carrier>();
  readonly #h2Idle = new Map<Http2Connection, Timer>();
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

  /**
   * Closes every connection it holds, answers still being read included, and
   * resolves once their sockets are closed. No idle timer fires after. It
   * can still be used after.
   */
  close(): Promise<void> {
    for (const timer of this.#h2Idle.values()) clearTimeout(timer);
    const idle = [...this.#idle.values()].flat();
    for (const { timer } of idle) clearTimeout(timer);
    for (const list of this.#h2.values()) for (const connection of list) connection.close();
    const carriers = [...this.#h2Carriers.values(), ...idle.map((i) => i.carrier), ...this.#busy];
    this.#h2.clear();
    this.#h2Carriers.clear();
    this.#h2Idle.clear();
    this.#idle.clear();
    this.#busy.clear();
    return Promise.all(carriers.map(shut)).then(() => undefined);
  }

  /** A connection open to `key` that can take a request now, if there is one. */
  #take(key: string): Opened | undefined {
    const shared = this.#h2.get(key);
    if (shared !== undefined) {
      const alive = shared.filter((connection) => connection.alive);
      for (const dead of shared.filter((connection) => !connection.alive)) this.#forget(dead);
      if (alive.length === 0) this.#h2.delete(key);
      else this.#h2.set(key, alive);
      const free = alive.find((connection) => connection.available);
      if (free !== undefined) {
        // Busy again: its idle timer starts over when its streams are done.
        cancel(this.#h2Idle.get(free));
        this.#h2Idle.delete(free);
        return { kind: 'h2', connection: free };
      }
    }
    const idle = this.#idle.get(key);
    while (idle !== undefined && idle.length > 0) {
      const { connection, carrier, since, timer } = idle.pop()!;
      clearTimeout(timer);
      // The timer closes it at idleMs; a clock that skipped ahead, or a
      // timer that never ran, is caught here.
      if (Date.now() - since <= this.#idleMs) return { kind: 'h1', connection, carrier, key };
      void shut(carrier);
    }
    return undefined;
  }

  /** Lets go of an HTTP/2 connection that is gone or closed. */
  #forget(connection: Http2Connection): void {
    cancel(this.#h2Idle.get(connection));
    this.#h2Idle.delete(connection);
    this.#h2Carriers.delete(connection);
  }

  /** Closes an HTTP/2 connection that has carried nothing for idleMs. */
  #expire(key: string, connection: Http2Connection): void {
    this.#h2Idle.delete(connection);
    if (!connection.idle) return;
    connection.close();
    this.#forget(connection);
    const rest = (this.#h2.get(key) ?? []).filter((other) => other !== connection);
    if (rest.length === 0) this.#h2.delete(key);
    else this.#h2.set(key, rest);
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
        return {
          kind: 'h1',
          connection: new Http1Connection(carrier),
          carrier,
          key,
          phases: carrier.phases,
        };
      }
      const connection: Http2Connection = new Http2Connection(carrier, profile, {
        close: () => void shut(carrier),
        onIdle: () => {
          if (!this.#keepAlive) {
            connection.close();
            return;
          }
          cancel(this.#h2Idle.get(connection));
          if (!connection.alive || !this.#h2Carriers.has(connection)) return;
          this.#h2Idle.set(
            connection,
            later(this.#idleMs, () => this.#expire(key, connection)),
          );
        },
      });
      if (this.#keepAlive) {
        this.#h2.set(key, [...(this.#h2.get(key) ?? []), connection]);
        this.#h2Carriers.set(connection, carrier);
      }
      return { kind: 'h2', connection, phases: carrier.phases };
    })();
    this.#opening.set(key, opening);
    try {
      return await opening;
    } finally {
      if (this.#opening.get(key) === opening) this.#opening.delete(key);
    }
  }

  async #on(opened: Opened, request: Request, options: ExchangeOptions): Promise<Response> {
    const response = await this.#send(opened, request, options);
    return timed(response, {
      start: options.start,
      reused: opened.phases === undefined,
      ...opened.phases,
      firstByte: Date.now() - options.start,
    });
  }

  async #send(opened: Opened, request: Request, options: ExchangeOptions): Promise<Response> {
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
    const stop = () => void shut(carrier);
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
      void shut(carrier);
      return;
    }
    const entry: Idle = {
      connection,
      carrier,
      since: Date.now(),
      // Closed at idleMs if nothing took it, so a place never asked for
      // again does not keep its socket open.
      timer: later(this.#idleMs, () => {
        const list = this.#idle.get(key) ?? [];
        const at = list.indexOf(entry);
        if (at === -1) return;
        list.splice(at, 1);
        if (list.length === 0) this.#idle.delete(key);
        void shut(carrier);
      }),
    };
    idle.push(entry);
    this.#idle.set(key, idle);
  }
}
