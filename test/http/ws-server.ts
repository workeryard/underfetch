/**
 * A WebSocket server in memory, for the tests: it answers the Upgrade and
 * reads the client's masked frames, so the client is checked against bytes
 * rather than against itself.
 */

import { createHash } from 'node:crypto';
import type { ByteSocket, Dial } from '../../src/net/socket';

/** A frame as a server sends it: unmasked. */
export function serverFrame(
  op: number,
  payload: Uint8Array | string,
  fin = true,
  mask = false,
): Uint8Array {
  const body = typeof payload === 'string' ? new TextEncoder().encode(payload) : payload;
  const first = (fin ? 0x80 : 0) | op;
  const maskBit = mask ? 0x80 : 0;
  const n = body.length;
  const head =
    n < 126
      ? [first, maskBit | n]
      : n < 65_536
        ? [first, maskBit | 126, n >> 8, n & 0xff]
        : [
            first,
            maskBit | 127,
            0,
            0,
            0,
            0,
            (n >>> 24) & 0xff,
            (n >> 16) & 0xff,
            (n >> 8) & 0xff,
            n & 0xff,
          ];
  const maskBytes = mask ? [1, 2, 3, 4] : [];
  return new Uint8Array([...head, ...maskBytes, ...body]);
}

export const closeFrame = (code: number, reason = '') =>
  serverFrame(0x8, new Uint8Array([code >> 8, code & 0xff, ...new TextEncoder().encode(reason)]));

export interface ClientFrame {
  fin: boolean;
  op: number;
  masked: boolean;
  payload: Uint8Array;
}

/** Takes one client frame off the front of `bytes`, if it is all there. */
function takeFrame(bytes: number[]): ClientFrame | null {
  if (bytes.length < 2) return null;
  let length = bytes[1]! & 0x7f;
  let at = 2;
  if (length === 126) {
    length = (bytes[2]! << 8) | bytes[3]!;
    at = 4;
  } else if (length === 127) {
    length = Number(new DataView(new Uint8Array(bytes.slice(2, 10)).buffer).getBigUint64(0));
    at = 10;
  }
  const masked = (bytes[1]! & 0x80) !== 0;
  const mask = masked ? bytes.slice(at, at + 4) : [0, 0, 0, 0];
  if (masked) at += 4;
  if (bytes.length < at + length) return null;
  const fin = (bytes[0]! & 0x80) !== 0;
  const op = bytes[0]! & 0x0f;
  const payload = new Uint8Array(bytes.slice(at, at + length)).map((b, i) => b ^ mask[i & 3]!);
  bytes.splice(0, at + length);
  return { fin, op, masked, payload };
}

/**
 * A WebSocket server in memory. It answers the Upgrade, then hands each
 * client frame to `onFrame`, which may reply; `greeting` goes out right after
 * the 101, before the client says anything.
 */
export interface ServerScript {
  status?: number;
  answerHeaders?: Record<string, string>;
  greeting?: Uint8Array[];
  onFrame?: (frame: ClientFrame, reply: (bytes: Uint8Array) => void) => void;
}

const echo: NonNullable<ServerScript['onFrame']> = (frame, reply) => {
  if (frame.op === 0x1 || frame.op === 0x2) reply(serverFrame(frame.op, frame.payload));
  if (frame.op === 0x8) reply(serverFrame(0x8, frame.payload));
};

export function server({
  status = 101,
  answerHeaders = {},
  greeting = [],
  onFrame = echo,
}: ServerScript = {}) {
  const frames: ClientFrame[] = [];
  let request = '';
  let closed = false;
  let end: () => void = () => undefined;
  const dial: Dial = () => {
    let push: (bytes: Uint8Array) => void = () => undefined;
    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        push = (bytes) => {
          if (!closed) controller.enqueue(bytes);
        };
        end = () => {
          if (!closed) controller.close();
          closed = true;
        };
      },
    });
    const pending: number[] = [];
    let upgraded = false;
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        pending.push(...chunk);
        if (!upgraded) {
          const text = new TextDecoder().decode(new Uint8Array(pending));
          const endOfHead = text.indexOf('\r\n\r\n');
          if (endOfHead < 0) return;
          request = text.slice(0, endOfHead);
          pending.splice(0, endOfHead + 4);
          upgraded = true;
          const key = /sec-websocket-key: (.*)/i.exec(request)?.[1]?.trim() ?? '';
          const accept = createHash('sha1')
            .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
            .digest('base64');
          const extra = Object.entries(answerHeaders).map(([k, v]) => `${k}: ${v}\r\n`);
          push(
            new TextEncoder().encode(
              status === 101
                ? `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n${extra.join('')}\r\n`
                : `HTTP/1.1 ${status} No\r\nContent-Length: 0\r\n${extra.join('')}\r\n`,
            ),
          );
          for (const frame of greeting) push(frame);
        }
        for (let frame = takeFrame(pending); frame !== null; frame = takeFrame(pending)) {
          frames.push(frame);
          onFrame(frame, push);
          if (frame.op === 0x8) end();
        }
      },
    });
    const socket: ByteSocket = {
      readable,
      writable,
      close: () => {
        end();
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  /** Ends the connection from the server's side, with no close frame. */
  const hangUp = () => end();
  return { dial, frames, request: () => request, hangUp };
}

export const tls = () => {
  throw new Error('no TLS in these tests');
};
