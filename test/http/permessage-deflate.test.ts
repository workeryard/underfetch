import * as zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { connectWebSocket } from '../../src/client/websocket';
import { acceptedDeflate, zlibInflater } from '../../src/http/permessage-deflate';
import { server, serverFrame, tls } from './ws-server';

const inflater = zlibInflater(zlib)!;
const RSV1 = 0x40;

describe('acceptedDeflate', () => {
  it('reads what servers answer', () => {
    expect(acceptedDeflate('permessage-deflate')).toEqual({ serverNoContextTakeover: false });
    expect(
      acceptedDeflate(
        'permessage-deflate; server_no_context_takeover; client_max_window_bits=15; server_max_window_bits="10"',
      ),
    ).toEqual({ serverNoContextTakeover: true });
  });

  it('refuses what it would not understand', () => {
    for (const value of [
      'x-webkit-deflate-frame',
      'permessage-deflate, permessage-deflate',
      'permessage-deflate; server_max_window_bits=7',
      'permessage-deflate; mystery',
      'permessage-deflate; server_no_context_takeover; server_no_context_takeover',
    ]) {
      expect(() => acceptedDeflate(value), value).toThrow();
    }
  });
});

describe('zlibInflater', () => {
  it('carries the window from one message to the next', async () => {
    const deflate = zlib.createDeflateRaw();
    const send = (text: string) =>
      new Promise<Uint8Array>((resolve) => {
        const parts: Buffer[] = [];
        const on = (chunk: Buffer) => parts.push(chunk);
        deflate.on('data', on);
        deflate.write(text);
        deflate.flush(zlib.constants.Z_SYNC_FLUSH, () => {
          deflate.off('data', on);
          const all = Buffer.concat(parts);
          resolve(new Uint8Array(all.subarray(0, all.length - 4)));
        });
      });

    const reader = inflater();
    const first = await send('hello hello hello world');
    const second = await send('hello hello hello world');
    // The second leans on the first's window: shorter, and unreadable alone.
    expect(second.length).toBeLessThan(first.length);
    expect(new TextDecoder().decode(await reader.inflate(first, 1000))).toBe(
      'hello hello hello world',
    );
    expect(new TextDecoder().decode(await reader.inflate(second, 1000))).toBe(
      'hello hello hello world',
    );
    reader.close();
  });

  it('refuses a message that inflates past the limit', async () => {
    const bomb = zlib.deflateRawSync(Buffer.alloc(1_000_000), {
      finishFlush: zlib.constants.Z_SYNC_FLUSH,
    });
    const reader = inflater();
    await expect(reader.inflate(new Uint8Array(bomb.subarray(0, -4)), 10_000)).rejects.toThrow(
      RangeError,
    );
    reader.close();
  });
});

describe('WebSocket with permessage-deflate', () => {
  const compressed = (text: string) => {
    const all = zlib.deflateRawSync(Buffer.from(text), {
      finishFlush: zlib.constants.Z_SYNC_FLUSH,
    });
    return new Uint8Array(all.subarray(0, all.length - 4));
  };

  it('offers it as Chrome does, and reads compressed and plain messages alike', async () => {
    const wire = server({
      answerHeaders: {
        'Sec-WebSocket-Extensions': 'permessage-deflate; server_no_context_takeover',
      },
      greeting: [
        serverFrame(0x1 | RSV1, compressed('squeezed text')),
        serverFrame(0x1, 'plain text'),
        serverFrame(0x2 | RSV1, compressed('\u0001\u0002')),
      ],
    });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      inflater,
    });

    expect(wire.request()).toContain(
      'Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits',
    );
    expect(socket.compressed).toBe(true);
    expect(await socket.recv()).toEqual({ type: 'text', data: 'squeezed text' });
    expect(await socket.recv()).toEqual({ type: 'text', data: 'plain text' });
    expect(await socket.recv()).toEqual({ type: 'binary', data: new Uint8Array([1, 2]) });

    // Ours go out uncompressed, which RFC 7692 allows.
    await socket.send('reply');
    expect(wire.frames.at(-1)?.payload).toEqual(new TextEncoder().encode('reply'));
  });

  it('inflates a compressed message split across fragments', async () => {
    const whole = compressed('fragmented and squeezed');
    const wire = server({
      answerHeaders: {
        'Sec-WebSocket-Extensions': 'permessage-deflate; server_no_context_takeover',
      },
      greeting: [
        serverFrame(0x1 | RSV1, whole.subarray(0, 5), false),
        serverFrame(0x0, whole.subarray(5), true),
      ],
    });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      inflater,
    });
    expect(await socket.recv()).toEqual({ type: 'text', data: 'fragmented and squeezed' });
  });

  it('fails RSV1 when nothing was agreed, and on a continuation', async () => {
    const plain = server({ greeting: [serverFrame(0x1 | RSV1, compressed('x'))] });
    const a = await connectWebSocket('ws://example.com/', { dial: plain.dial, tls, inflater });
    await expect(a.socket.recv()).rejects.toThrow(/reserved bit/);
    expect(a.socket.closed?.code).toBe(1002);

    const agreed = server({
      answerHeaders: { 'Sec-WebSocket-Extensions': 'permessage-deflate' },
      greeting: [serverFrame(0x1, 'a', false), serverFrame(0x0 | RSV1, 'b')],
    });
    const b = await connectWebSocket('ws://example.com/', { dial: agreed.dial, tls, inflater });
    await expect(b.socket.recv()).rejects.toThrow(/RSV1/);
  });

  it('closes with 1007 on bytes that do not inflate', async () => {
    const wire = server({
      answerHeaders: { 'Sec-WebSocket-Extensions': 'permessage-deflate' },
      greeting: [serverFrame(0x1 | RSV1, new Uint8Array([0xff, 0xff, 0xff, 0xff]))],
    });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      inflater,
    });
    await expect(socket.recv()).rejects.toThrow(/inflate/);
    expect(socket.closed?.code).toBe(1007);
  });

  it('does not offer it without an inflater', async () => {
    const wire = server();
    await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });
    expect(wire.request()).not.toContain('Sec-WebSocket-Extensions');
  });
});
