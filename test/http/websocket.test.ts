import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { connectWebSocket, WebSocketRefused } from '../../src/client/websocket';
import { Session } from '../../src/client/session';
import type { ByteSocket, Dial } from '../../src/net/socket';

/** A frame as a server sends it: unmasked. */
function serverFrame(
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

const closeFrame = (code: number, reason = '') =>
  serverFrame(0x8, new Uint8Array([code >> 8, code & 0xff, ...new TextEncoder().encode(reason)]));

interface ClientFrame {
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
interface ServerScript {
  status?: number;
  answerHeaders?: Record<string, string>;
  greeting?: Uint8Array[];
  onFrame?: (frame: ClientFrame, reply: (bytes: Uint8Array) => void) => void;
}

const echo: NonNullable<ServerScript['onFrame']> = (frame, reply) => {
  if (frame.op === 0x1 || frame.op === 0x2) reply(serverFrame(frame.op, frame.payload));
  if (frame.op === 0x8) reply(serverFrame(0x8, frame.payload));
};

function server({
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

const tls = () => {
  throw new Error('no TLS in these tests');
};

describe('WebSocket', () => {
  it('upgrades, echoes text and bytes, and closes cleanly', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/chat?room=1', {
      dial: wire.dial,
      tls,
    });

    await socket.send('hello');
    expect(await socket.recv()).toEqual({ type: 'text', data: 'hello' });
    await socket.send(new Uint8Array([1, 2, 3]));
    expect(await socket.recv()).toEqual({ type: 'binary', data: new Uint8Array([1, 2, 3]) });

    expect(await socket.close(1000, 'bye')).toEqual({ code: 1000, reason: 'bye' });
    expect(wire.frames.every((f) => f.masked)).toBe(true);
    expect(wire.request()).toMatch(/^GET \/chat\?room=1 HTTP\/1.1\r\nHost: example.com\r\n/);
    expect(wire.request()).toContain('User-Agent: underfetch/0.1');
    expect(wire.request()).not.toContain('Sec-WebSocket-Extensions');
  });

  it('carries a message longer than one short frame', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });
    const big = 'x'.repeat(70_000);
    await socket.send(big);
    expect(wire.frames[0]?.payload.length).toBe(70_000);
    // The echo comes back with a 64-bit length, which the reader must follow.
    expect(await socket.recv()).toEqual({ type: 'text', data: big });
  });

  it('joins fragments, answering a ping that arrives between them', async () => {
    const wire = server({
      greeting: [
        serverFrame(0x1, 'hel', false),
        serverFrame(0x9, 'are you there'),
        serverFrame(0x0, 'lo', true),
      ],
    });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    expect(await socket.recv()).toEqual({ type: 'text', data: 'hello' });
    const pong = wire.frames.find((f) => f.op === 0xa);
    expect(new TextDecoder().decode(pong?.payload)).toBe('are you there');
  });

  it('answers a close the server starts, and then reads nothing more', async () => {
    const wire = server({ greeting: [serverFrame(0x1, 'last'), closeFrame(1001, 'going away')] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    const seen = [];
    for await (const message of socket) seen.push(message);
    expect(seen).toEqual([{ type: 'text', data: 'last' }]);
    expect(socket.closed).toEqual({ code: 1001, reason: 'going away' });
    const answer = wire.frames.find((f) => f.op === 0x8);
    expect([...(answer?.payload ?? [])]).toEqual([0x03, 0xe9]);
    await expect(socket.send('late')).rejects.toThrow(/closing/);
  });

  it('fails a masked server frame with 1002', async () => {
    const wire = server({ greeting: [serverFrame(0x1, 'sneaky', true, true)] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    await expect(socket.recv()).rejects.toThrow(/masked/);
    expect(socket.closed?.code).toBe(1002);
  });

  it('fails text that is not UTF-8 with 1007', async () => {
    const wire = server({ greeting: [serverFrame(0x1, new Uint8Array([0xff, 0xfe]))] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    await expect(socket.recv()).rejects.toThrow(/UTF-8/);
    expect(socket.closed?.code).toBe(1007);
  });

  it('fails a message over the limit with 1009', async () => {
    const wire = server({ greeting: [serverFrame(0x2, new Uint8Array(200))] });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      maxMessageBytes: 100,
    });

    await expect(socket.recv()).rejects.toThrow(/over the limit/);
    expect(socket.closed?.code).toBe(1009);
  });

  it('reports a connection that ends without a close as 1006', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });
    wire.hangUp();

    expect(await socket.recv()).toBeNull();
    expect(socket.closed).toEqual({ code: 1006, reason: '' });
  });

  it('refuses a server that does not upgrade, keeping its status', async () => {
    const wire = server({ status: 403 });
    const error = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(WebSocketRefused);
    expect((error as WebSocketRefused).status).toBe(403);
  });

  it('refuses a subprotocol or an extension it never offered', async () => {
    for (const answerHeaders of [
      { 'Sec-WebSocket-Protocol': 'chat' },
      { 'Sec-WebSocket-Extensions': 'permessage-deflate' },
    ]) {
      const wire = server({ answerHeaders });
      await expect(connectWebSocket('ws://example.com/', { dial: wire.dial, tls })).rejects.toThrow(
        /never offered/,
      );
    }
  });

  it('accepts the subprotocol it offered', async () => {
    const wire = server({ answerHeaders: { 'Sec-WebSocket-Protocol': 'graphql-ws' } });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      protocols: ['graphql-ws', 'chat'],
    });
    expect(socket.protocol).toBe('graphql-ws');
    expect(wire.request()).toContain('Sec-WebSocket-Protocol: graphql-ws, chat');
  });
});

describe('Session.websocket', () => {
  it('sends the session headers a browser would, and its cookies, and keeps what it is set', async () => {
    const wire = server({ answerHeaders: { 'Set-Cookie': 'ws=1; Path=/' } });
    const session = new Session({
      dial: wire.dial,
      tls,
      cookies: true,
      headers: {
        'user-agent': 'Mozilla/5.0 test',
        'accept-language': 'en-US',
        'sec-fetch-mode': 'navigate',
        accept: 'text/html',
        'x-api-key': 'k',
      },
    });
    session.cookies?.store(new URL('http://example.com/'), ['sid=abc; Path=/']);

    const socket = await session.websocket('ws://example.com/live', {
      headers: { origin: 'http://example.com' },
    });
    const head = wire.request();
    expect(head).toContain('User-Agent: Mozilla/5.0 test');
    expect(head).toContain('Origin: http://example.com');
    expect(head).toContain('Accept-Language: en-US');
    expect(head).toContain('Cookie: sid=abc');
    expect(head).toContain('x-api-key: k');
    expect(head).not.toContain('sec-fetch-mode');
    expect(head).not.toMatch(/^accept:/im);
    // The Chrome order: Connection before User-Agent, Upgrade after it.
    expect(head.indexOf('Connection: Upgrade')).toBeLessThan(head.indexOf('User-Agent'));
    expect(head.indexOf('User-Agent')).toBeLessThan(head.indexOf('Upgrade: websocket'));
    expect(session.cookies?.header(new URL('http://example.com/'))).toContain('ws=1');
    await socket.close();
  });
});
