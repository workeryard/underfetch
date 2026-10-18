/** Servers the pool tests talk to, over sockets in memory. */

import { Session } from '../../src/client/session';
import { Hpack, type Header } from '../../src/http/h2/hpack';
import { encodeFrame, encodeSettings, Flags, FrameType, PREFACE } from '../../src/http/h2/frames';
import type { ByteSocket, Dial } from '../../src/net/socket';
import type { TlsSession } from '../../src/tls/tunnel';

/** TLS that encrypts nothing and settles ALPN on `protocol`. */
export class Passthrough implements TlsSession {
  handshaking = false;
  #plain: number[] = [];
  #out: number[] = [];
  constructor(readonly protocol?: string) {}
  receive(data: Uint8Array): number {
    this.#plain.push(...data);
    return data.length;
  }
  outgoing(): Uint8Array {
    const out = new Uint8Array(this.#out);
    this.#out = [];
    return out;
  }
  send(data: Uint8Array): void {
    this.#out.push(...data);
  }
  plaintext(): Uint8Array {
    const plain = new Uint8Array(this.#plain);
    this.#plain = [];
    return plain;
  }
  close(): void {}
}

export const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
export const ok = (body: string, extra = '') =>
  `HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n${extra}\r\n${body}`;

/**
 * An HTTP/1.1 server that keeps connections open: it reads whole requests
 * off each one and answers each with what `reply` says. `null` hangs up
 * instead, as a server does with a connection idle too long.
 */
export function http1Server(reply: (request: string, connection: number) => string | null) {
  const requests: string[][] = [];
  let closed = 0;
  const dial: Dial = () => {
    const connection = requests.length;
    const seen: string[] = [];
    requests.push(seen);
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    let buffer = '';
    let open = true;
    const hangUp = () => {
      if (!open) return;
      open = false;
      controller.close();
    };
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({ start: (c) => void (controller = c) }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          buffer += text(chunk);
          for (;;) {
            const end = buffer.indexOf('\r\n\r\n');
            if (end === -1) return;
            const length = Number(/content-length: (\d+)/i.exec(buffer.slice(0, end))?.[1] ?? 0);
            if (buffer.length < end + 4 + length) return;
            const request = buffer.slice(0, end + 4 + length);
            buffer = buffer.slice(end + 4 + length);
            seen.push(request);
            if (!open) continue;
            const answer = reply(request, connection);
            if (answer === null) hangUp();
            else controller.enqueue(new TextEncoder().encode(answer));
          }
        },
      }),
      close: () => {
        closed += 1;
        hangUp();
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, requests, closed: () => closed };
}

export const on = (dial: Dial, protocol?: string, defaults = {}) =>
  new Session({ dial, tls: () => new Passthrough(protocol), ...defaults });

interface SeenFrame {
  type: number;
  flags: number;
  stream: number;
  payload: Uint8Array;
}

/**
 * An HTTP/2 server: it reads frames off each connection and hands each
 * request's headers to `onRequest`, which answers through `send`.
 */
export function http2Server(
  onRequest: (
    stream: number,
    headers: Header[],
    send: (frame: Uint8Array) => void,
    connection: number,
  ) => void,
) {
  const frames: SeenFrame[][] = [];
  let closed = 0;
  const dial: Dial = () => {
    const connection = frames.length;
    const seen: SeenFrame[] = [];
    frames.push(seen);
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    let buffer = new Uint8Array(0);
    let preface = false;
    const hpack = new Hpack();
    const send = (frame: Uint8Array) => controller.enqueue(frame);
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({
        start(c) {
          controller = c;
          c.enqueue(encodeFrame(FrameType.Settings, 0, 0, encodeSettings([])));
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          const joined = new Uint8Array(buffer.length + chunk.length);
          joined.set(buffer);
          joined.set(chunk, buffer.length);
          buffer = joined;
          if (!preface) {
            if (buffer.length < PREFACE.length) return;
            buffer = buffer.subarray(PREFACE.length);
            preface = true;
          }
          while (buffer.length >= 9) {
            const length = (buffer[0]! << 16) | (buffer[1]! << 8) | buffer[2]!;
            if (buffer.length < 9 + length) return;
            const view = new DataView(buffer.buffer, buffer.byteOffset);
            const frame = {
              type: buffer[3]!,
              flags: buffer[4]!,
              stream: view.getUint32(5) & 0x7fffffff,
              payload: buffer.slice(9, 9 + length),
            };
            buffer = buffer.subarray(9 + length);
            seen.push(frame);
            if (frame.type === FrameType.Headers) {
              const block =
                (frame.flags & Flags.Priority) !== 0 ? frame.payload.subarray(5) : frame.payload;
              onRequest(frame.stream, hpack.decode(block), send, connection);
            }
          }
        },
      }),
      close: () => {
        closed += 1;
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, frames, closed: () => closed };
}

export const headersFrame = (stream: number, status: number, end = false) =>
  encodeFrame(
    FrameType.Headers,
    Flags.EndHeaders | (end ? Flags.EndStream : 0),
    stream,
    new Hpack().encode([[':status', String(status)]]),
  );
export const dataFrame = (stream: number, body: string, end = true) =>
  encodeFrame(FrameType.Data, end ? Flags.EndStream : 0, stream, new TextEncoder().encode(body));
export const path = (headers: Header[]) => headers.find(([name]) => name === ':path')![1];
