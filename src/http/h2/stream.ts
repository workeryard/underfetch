/**
 * One request's stream on an HTTP/2 connection: its answer, the body as the
 * caller reads it, and the request body going out within the server's window.
 * The connection reads the frames and moves them here; what a stream needs of
 * the connection in turn is `StreamHost`.
 */

import { decompressed, type Decoders } from '../decompress';
import { encodeFrame, Flags, FrameType, Http2Error } from './frames';
import type { Header } from './hpack';
import { withLast } from './flow';

export interface StreamHost {
  /** The largest frame the server takes. */
  maxFrame(): number;
  /** What is left of the connection's send window. */
  window(): number;
  /** Takes `bytes` off the connection's send window. */
  spend(bytes: number): void;
  write(frame: Uint8Array): Promise<void>;
  /** `cost` bytes of the stream's body have been read by the caller. */
  consumed(stream: Http2Stream, cost: number): void;
  /** Lets go of the stream if both sides are done with it. */
  settle(stream: Http2Stream): void;
  /** Our side gives up on the stream. */
  cancel(stream: Http2Stream, reason: Error): void;
}

export class Http2Stream {
  /** What the server still lets us send on it. */
  send: number;
  answered = false;
  /** The server has ended its side. */
  ended = false;
  /** Its body has been read to the end, or there was none. */
  drained = false;
  /** An upload is still going. */
  sending = false;
  /** We have ended our side. */
  sentEnd = false;
  error: Error | undefined;
  /** Bytes read and not yet given back to the server's window. */
  unacked = 0;
  /** The weight its HEADERS carried, which stands for its priority. */
  weight = 0;
  unlisten: () => void = () => undefined;
  readonly answer: Promise<Response>;

  /** Body bytes not yet read, each with what it cost of the window. */
  readonly #chunks: { data: Uint8Array; cost: number }[] = [];
  /** Wakes a body read waiting for a chunk. */
  #wake: (() => void) | undefined;
  /** Wakes an upload waiting for window. */
  #room: (() => void) | undefined;
  #resolve: (response: Response) => void = () => undefined;
  #reject: (error: Error) => void = () => undefined;

  constructor(
    readonly id: number,
    window: number,
    readonly decoders: Decoders,
  ) {
    this.send = window;
    this.answer = new Promise<Response>((resolve, reject) => {
      this.#resolve = resolve;
      this.#reject = reject;
    });
    // An answer nobody waits for any more must not surface as unhandled.
    this.answer.catch(() => undefined);
  }

  /** Gives up on the stream, by `cancel`, when `signal` aborts. */
  watch(signal: AbortSignal | undefined, cancel: (reason: Error) => void): void {
    if (signal === undefined) return;
    const abort = () => cancel(signal.reason as Error);
    if (signal.aborted) abort();
    signal.addEventListener('abort', abort, { once: true });
    this.unlisten = () => signal.removeEventListener('abort', abort);
  }

  /** Something changed that a waiting upload or read should look at. */
  nudge(): void {
    this.#room?.();
    this.#wake?.();
  }

  /** The server has ended its side. */
  end(): void {
    this.ended = true;
    this.nudge();
  }

  fail(error: Error): void {
    this.error = error;
    if (!this.answered) this.#reject(error);
    this.nudge();
  }

  data(data: Uint8Array, cost: number): void {
    this.#chunks.push({ data, cost });
    this.#wake?.();
  }

  /**
   * A header block for this stream: the answer's, which is handed back with
   * a body unless the block ended the stream, or else its trailers, which a
   * Response has nowhere to put. False for one that does not count — a 1xx,
   * or one so broken the stream is given up.
   */
  headers(host: StreamHost, headers: readonly Header[], endStream: boolean): boolean {
    if (this.answered) return true;
    const status = Number(headers.find(([name]) => name === ':status')?.[1] ?? 0);
    if (!Number.isInteger(status) || status < 100) {
      host.cancel(this, new Http2Error('the server sent no usable :status'));
      return false;
    }
    // A 1xx is informational: the real headers are still to come.
    if (status < 200) return false;
    this.answered = true;
    const out = new Headers();
    for (const [name, value] of headers) {
      if (!name.startsWith(':')) out.append(name, value);
    }
    if (endStream) {
      this.drained = true;
      this.#resolve(new Response(null, { status, headers: out }));
      return true;
    }
    // As on HTTP/1.1: the caller asked for a response, not for gzip.
    const body = decompressed(this.#body(host), out, this.decoders);
    this.#resolve(new Response(body, { status, headers: out }));
    return true;
  }

  /** The body as the caller reads it; reading is what reopens the window. */
  #body(host: StreamHost): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
      pull: async (controller) => {
        for (;;) {
          const next = this.#chunks.shift();
          if (next !== undefined) {
            host.consumed(this, next.cost);
            if (next.data.length === 0) continue;
            controller.enqueue(next.data);
            return;
          }
          if (this.error !== undefined) throw this.error;
          if (this.ended) {
            this.drained = true;
            host.settle(this);
            controller.close();
            return;
          }
          await new Promise<void>((resolve) => (this.#wake = resolve));
          this.#wake = undefined;
        }
      },
      cancel: () => host.cancel(this, new Http2Error('the body was cancelled')),
    });
  }

  /**
   * Sends the body in frames the server has room for, waiting for its window
   * updates when there is none. It stops once the server has ended the
   * stream: it has answered without the rest.
   */
  async upload(host: StreamHost, body: ReadableStream<Uint8Array>): Promise<void> {
    this.sending = true;
    const stopped = () => this.ended || this.error !== undefined;
    try {
      let sent = false;
      for await (const [chunk, last] of withLast(body.getReader())) {
        for (let offset = 0; offset < chunk.length;) {
          if (stopped()) return;
          const room = Math.min(host.maxFrame(), this.send, host.window());
          if (room <= 0) {
            await new Promise<void>((resolve) => (this.#room = resolve));
            this.#room = undefined;
            continue;
          }
          const piece = chunk.subarray(offset, offset + room);
          offset += piece.length;
          const end = last && offset === chunk.length;
          this.send -= piece.length;
          host.spend(piece.length);
          if (end) this.sentEnd = true;
          await host.write(encodeFrame(FrameType.Data, end ? Flags.EndStream : 0, this.id, piece));
          sent = true;
        }
      }
      // A stream that turned out empty still has to be ended.
      if (!sent && !stopped()) {
        this.sentEnd = true;
        await host.write(encodeFrame(FrameType.Data, Flags.EndStream, this.id, new Uint8Array(0)));
      }
    } catch (error) {
      host.cancel(this, error as Error);
    } finally {
      this.sending = false;
      host.settle(this);
    }
  }
}
