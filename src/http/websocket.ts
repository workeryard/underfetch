/**
 * WebSocket (RFC 6455) over a connection that has already said 101.
 *
 * Pull-based rather than evented, as impers has it: `recv()` reads the next
 * message when the caller asks, which is what a Worker wants — nothing runs
 * unless something awaits it. Pings are answered on the way past, and a
 * close is answered and finished as the RFC asks.
 *
 * permessage-deflate is not offered, so frames never arrive compressed.
 */

import type { ByteReader } from '../net/bytes';

export class WebSocketError extends Error {
  override name = 'WebSocketError';
}

export type WebSocketMessage =
  { type: 'text'; data: string } | { type: 'binary'; data: Uint8Array };

/** How the connection ended. 1006 means the connection went without a close frame. */
export interface WebSocketClose {
  code: number;
  reason: string;
}

const Op = {
  Continuation: 0x0,
  Text: 0x1,
  Binary: 0x2,
  Close: 0x8,
  Ping: 0x9,
  Pong: 0xa,
} as const;

/** A frame as a client must send it: masked, with a fresh key each time. */
export function encodeFrame(op: number, payload: Uint8Array, fin = true): Uint8Array {
  const length = payload.length;
  const lengthBytes = length < 126 ? 0 : length < 65_536 ? 2 : 8;
  const out = new Uint8Array(2 + lengthBytes + 4 + length);
  const view = new DataView(out.buffer);
  out[0] = (fin ? 0x80 : 0) | op;
  if (lengthBytes === 0) out[1] = 0x80 | length;
  else if (lengthBytes === 2) {
    out[1] = 0x80 | 126;
    view.setUint16(2, length);
  } else {
    out[1] = 0x80 | 127;
    view.setUint32(2, Math.floor(length / 2 ** 32));
    view.setUint32(6, length >>> 0);
  }
  const at = 2 + lengthBytes;
  const mask = crypto.getRandomValues(new Uint8Array(4));
  out.set(mask, at);
  for (let i = 0; i < length; i++) out[at + 4 + i] = payload[i]! ^ mask[i & 3]!;
  return out;
}

interface Frame {
  fin: boolean;
  op: number;
  payload: Uint8Array;
}

/** Closes that say something went wrong, by what went wrong. */
const PROTOCOL = 1002;
const INVALID_DATA = 1007;
const TOO_BIG = 1009;

class Violation extends WebSocketError {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

async function readFrame(reader: ByteReader, limit: number): Promise<Frame> {
  const [first, second] = await reader.exactly(2);
  if ((first! & 0x70) !== 0) throw new Violation(PROTOCOL, 'a frame set a reserved bit');
  if ((second! & 0x80) !== 0) throw new Violation(PROTOCOL, 'the server masked a frame');
  const op = first! & 0x0f;
  let length = second! & 0x7f;
  if (length === 126) {
    length = new DataView((await reader.exactly(2)).slice().buffer).getUint16(0);
  } else if (length === 127) {
    const view = new DataView((await reader.exactly(8)).slice().buffer);
    length = view.getUint32(0) * 2 ** 32 + view.getUint32(4);
  }
  const fin = (first! & 0x80) !== 0;
  if (op >= 0x8 && (length > 125 || !fin)) {
    throw new Violation(PROTOCOL, 'a control frame was fragmented or too long');
  }
  if (length > limit) throw new Violation(TOO_BIG, `a frame of ${length} bytes is over the limit`);
  return { fin, op, payload: length === 0 ? new Uint8Array(0) : await reader.exactly(length) };
}

function joined(parts: Uint8Array[]): Uint8Array {
  if (parts.length === 1) return parts[0]!;
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** How long `close()` waits for the server to answer before hanging up anyway. */
const CLOSE_WAIT_MS = 5_000;

export class WebSocketConnection implements AsyncIterable<WebSocketMessage> {
  readonly #reader: ByteReader;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  readonly #shut: () => void;
  readonly #limit: number;
  /** Frames go out one at a time, in order, however many callers send. */
  #writing: Promise<void> = Promise.resolve();
  /** And messages are read one caller at a time. */
  #reading: Promise<unknown> = Promise.resolve();
  #sentClose = false;
  #closed: WebSocketClose | null = null;

  constructor(
    reader: ByteReader,
    writable: WritableStream<Uint8Array>,
    shut: () => void,
    /** The subprotocol the server chose, or '' for none. */
    readonly protocol: string,
    maxMessageBytes: number,
  ) {
    this.#reader = reader;
    this.#writer = writable.getWriter();
    this.#shut = shut;
    this.#limit = maxMessageBytes;
  }

  /** How it ended, once it has; null while it is open. */
  get closed(): WebSocketClose | null {
    return this.#closed;
  }

  #write(frame: Uint8Array): Promise<void> {
    const next = this.#writing.then(() => this.#writer.write(frame));
    this.#writing = next.catch(() => undefined);
    return next;
  }

  /** A string goes as text, anything else as binary. */
  send(data: string | Uint8Array | ArrayBuffer): Promise<void> {
    if (this.#sentClose || this.#closed) {
      return Promise.reject(new WebSocketError('the connection is closing'));
    }
    if (typeof data === 'string')
      return this.#write(encodeFrame(Op.Text, new TextEncoder().encode(data)));
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    return this.#write(encodeFrame(Op.Binary, bytes));
  }

  ping(data: string | Uint8Array = new Uint8Array(0)): Promise<void> {
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    if (bytes.length > 125)
      return Promise.reject(new WebSocketError('a ping carries 125 bytes at most'));
    return this.#write(encodeFrame(Op.Ping, bytes));
  }

  /**
   * The next message, or null once the connection has closed — `closed` then
   * says how. Pings met on the way are answered.
   */
  recv(): Promise<WebSocketMessage | null> {
    const next = this.#reading.then(() => this.#next());
    this.#reading = next.catch(() => undefined);
    return next;
  }

  async *[Symbol.asyncIterator](): AsyncIterator<WebSocketMessage> {
    for (;;) {
      const message = await this.recv();
      if (message === null) return;
      yield message;
    }
  }

  async #next(): Promise<WebSocketMessage | null> {
    if (this.#closed) return null;
    const parts: Uint8Array[] = [];
    let size = 0;
    let op: number | undefined;
    try {
      for (;;) {
        const frame = await readFrame(this.#reader, this.#limit - size);
        if (frame.op === Op.Ping) {
          if (!this.#sentClose)
            void this.#write(encodeFrame(Op.Pong, frame.payload)).catch(() => undefined);
          continue;
        }
        if (frame.op === Op.Pong) continue;
        if (frame.op === Op.Close) {
          await this.#answerClose(frame.payload);
          return null;
        }
        if (frame.op === Op.Continuation) {
          if (op === undefined) throw new Violation(PROTOCOL, 'a continuation began nothing');
        } else if (frame.op === Op.Text || frame.op === Op.Binary) {
          if (op !== undefined) throw new Violation(PROTOCOL, 'a message began inside another');
          op = frame.op;
        } else {
          throw new Violation(PROTOCOL, `unknown opcode ${frame.op}`);
        }
        parts.push(frame.payload);
        size += frame.payload.length;
        if (!frame.fin) continue;

        const data = joined(parts);
        if (op === Op.Binary) return { type: 'binary', data };
        try {
          return { type: 'text', data: utf8.decode(data) };
        } catch {
          throw new Violation(INVALID_DATA, 'a text message was not UTF-8');
        }
      }
    } catch (error) {
      if (error instanceof Violation) {
        await this.#fail(error.code, error.message);
        throw error;
      }
      // The connection went without a close frame: RFC 6455 calls that 1006.
      if (!this.#closed) this.#closed = { code: 1006, reason: '' };
      this.#shut();
      return null;
    }
  }

  async #answerClose(payload: Uint8Array): Promise<void> {
    let code = 1005;
    let reason = '';
    if (payload.length >= 2) {
      code = new DataView(payload.slice().buffer).getUint16(0);
      reason = new TextDecoder().decode(payload.subarray(2));
    }
    this.#closed = { code, reason };
    if (!this.#sentClose) {
      this.#sentClose = true;
      // Echoing the code is how the RFC says "agreed".
      await this.#write(encodeFrame(Op.Close, payload.subarray(0, 2))).catch(() => undefined);
    }
    this.#shut();
  }

  async #fail(code: number, reason: string): Promise<void> {
    this.#closed = { code, reason };
    if (!this.#sentClose) {
      this.#sentClose = true;
      await this.#write(closePayload(Op.Close, code, reason)).catch(() => undefined);
    }
    this.#shut();
  }

  /**
   * Says goodbye and waits for the server to agree, up to five seconds;
   * messages still arriving meanwhile are dropped. Resolves with how it ended.
   */
  async close(code = 1000, reason = ''): Promise<WebSocketClose> {
    if (this.#closed) return this.#closed;
    if (!this.#sentClose) {
      this.#sentClose = true;
      await this.#write(closePayload(Op.Close, code, reason)).catch(() => undefined);
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, CLOSE_WAIT_MS);
    });
    const drained = (async () => {
      while ((await this.recv().catch(() => null)) !== null);
    })();
    await Promise.race([drained, late]);
    clearTimeout(timer);
    if (!this.#closed) this.#closed = { code: 1006, reason: '' };
    this.#shut();
    return this.#closed;
  }
}

function closePayload(op: number, code: number, reason: string): Uint8Array {
  const text = new TextEncoder().encode(reason).subarray(0, 123);
  const payload = new Uint8Array(2 + text.length);
  new DataView(payload.buffer).setUint16(0, code);
  payload.set(text, 2);
  return encodeFrame(op, payload);
}
