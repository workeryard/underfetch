import { describe, expect, it } from 'vitest';
import { Hpack } from '../src/h2/hpack';
import { http2Fetch, DEFAULT_PROFILE } from '../src/h2/connection';
import {
  decodeSettings,
  encodeFrame,
  encodeSettings,
  Flags,
  FrameType,
  Http2Error,
  PREFACE,
  Setting,
} from '../src/h2/frames';
import type { Http2Socket } from '../src/h2/connection';

/** Splits a stream of frames the way a peer would read them. */
function framesIn(
  written: number[],
): { type: number; flags: number; stream: number; payload: Uint8Array }[] {
  const data = new Uint8Array(written);
  const view = new DataView(data.buffer);
  const out = [];
  let at = PREFACE.length; // the preface leads and is not a frame
  while (at + 9 <= data.length) {
    const length = (data[at]! << 16) | view.getUint16(at + 1);
    out.push({
      type: data[at + 3]!,
      flags: data[at + 4]!,
      stream: view.getUint32(at + 5) & 0x7fffffff,
      payload: data.subarray(at + 9, at + 9 + length),
    });
    at += 9 + length;
  }
  return out;
}

const serverHeaders = (headers: readonly (readonly [string, string])[], flags: number) =>
  encodeFrame(FrameType.Headers, Flags.EndHeaders | flags, 1, new Hpack().encode(headers));

function socketOf(answer: Uint8Array[]): { socket: Http2Socket; written: number[] } {
  const written: number[] = [];
  return {
    socket: {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const frame of answer) controller.enqueue(frame);
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
    },
    written,
  };
}

const SETTINGS = encodeFrame(
  FrameType.Settings,
  0,
  0,
  encodeSettings([[Setting.MaxFrameSize, 16384]]),
);
const OK = serverHeaders(
  [
    [':status', '200'],
    ['content-type', 'application/json'],
  ],
  0,
);
const data = (text: string, end = true) =>
  encodeFrame(FrameType.Data, end ? Flags.EndStream : 0, 1, new TextEncoder().encode(text));

describe('http2', () => {
  it('opens with the preface, its settings, and a window update', async () => {
    const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
    await (await http2Fetch(socket, new Request('https://example.com/'))).text();

    expect(written.slice(0, PREFACE.length)).toEqual([...PREFACE]);
    const frames = framesIn(written);
    expect(frames[0]?.type).toBe(FrameType.Settings);
    // The settings go out in the order the profile gave them.
    expect([...decodeSettings(frames[0]!.payload).keys()]).toEqual(
      DEFAULT_PROFILE.settings.map(([id]) => id),
    );
    expect(frames[1]?.type).toBe(FrameType.WindowUpdate);
    expect(
      new DataView(frames[1]!.payload.buffer, frames[1]!.payload.byteOffset).getUint32(0),
    ).toBe(DEFAULT_PROFILE.windowUpdate);
  });

  it('sends the pseudo-headers in the profile order', async () => {
    const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
    await (
      await http2Fetch(
        socket,
        new Request('https://api.example.com/v1/models?a=1', {
          headers: { authorization: 'Bearer sk' },
        }),
      )
    ).text();

    const headers = framesIn(written).find((f) => f.type === FrameType.Headers);
    const decoded = new Hpack().decode(headers!.payload);
    expect(decoded.slice(0, 4).map(([name]) => name)).toEqual([
      ':method',
      ':authority',
      ':scheme',
      ':path',
    ]);
    expect(decoded).toContainEqual([':path', '/v1/models?a=1']);
    expect(decoded).toContainEqual([':authority', 'api.example.com']);
    expect(decoded).toContainEqual(['authorization', 'Bearer sk']);
  });

  it('acknowledges the server settings', async () => {
    const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
    await (await http2Fetch(socket, new Request('https://example.com/'))).text();

    const acks = framesIn(written).filter(
      (f) => f.type === FrameType.Settings && (f.flags & Flags.Ack) !== 0,
    );
    expect(acks).toHaveLength(1);
  });

  it('reads a body split across frames, one piece at a time', async () => {
    const { socket } = socketOf([SETTINGS, OK, data('first ', false), data('second')]);
    const response = await http2Fetch(socket, new Request('https://example.com/'));

    const reader = response.body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('first ');
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('second');
    expect((await reader.read()).done).toBe(true);
  });

  it('keeps the status and headers, and drops the pseudo-headers', async () => {
    const { socket } = socketOf([
      SETTINGS,
      serverHeaders(
        [
          [':status', '404'],
          ['content-type', 'text/plain'],
          ['set-cookie', 'a=1'],
          ['set-cookie', 'b=2'],
        ],
        Flags.EndStream,
      ),
    ]);
    const response = await http2Fetch(socket, new Request('https://example.com/'));

    expect(response.status).toBe(404);
    expect(response.headers.get('content-type')).toBe('text/plain');
    expect(response.headers.getSetCookie()).toEqual(['a=1', 'b=2']);
    expect(response.body).toBeNull();
  });

  it('waits past an informational response for the real one', async () => {
    const { socket } = socketOf([
      SETTINGS,
      serverHeaders([[':status', '103']], 0),
      serverHeaders([[':status', '200']], Flags.EndStream),
    ]);
    expect((await http2Fetch(socket, new Request('https://example.com/'))).status).toBe(200);
  });

  it('says why the server hung up', async () => {
    const goAway = new Uint8Array(8);
    new DataView(goAway.buffer).setUint32(4, 11); // ENHANCE_YOUR_CALM
    const { socket } = socketOf([SETTINGS, encodeFrame(FrameType.GoAway, 0, 0, goAway)]);

    await expect(http2Fetch(socket, new Request('https://example.com/'))).rejects.toThrow(
      /enhance your calm/,
    );
  });

  it('says why the stream was reset', async () => {
    const reset = new Uint8Array(4);
    new DataView(reset.buffer).setUint32(0, 7); // REFUSED_STREAM
    const { socket } = socketOf([SETTINGS, encodeFrame(FrameType.RstStream, 0, 1, reset)]);

    await expect(http2Fetch(socket, new Request('https://example.com/'))).rejects.toThrow(
      Http2Error,
    );
  });

  it('answers a ping so the connection is not dropped under it', async () => {
    const ping = encodeFrame(FrameType.Ping, 0, 0, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
    const { socket, written } = socketOf([SETTINGS, ping, OK, data('{}')]);
    await (await http2Fetch(socket, new Request('https://example.com/'))).text();

    const pong = framesIn(written).find(
      (f) => f.type === FrameType.Ping && (f.flags & Flags.Ack) !== 0,
    );
    expect([...(pong?.payload ?? [])]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('sends a request body as DATA and ends the stream after it', async () => {
    const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
    await (
      await http2Fetch(
        socket,
        new Request('https://example.com/', { method: 'POST', body: '{"a":1}' }),
      )
    ).text();

    const frames = framesIn(written);
    const headers = frames.find((f) => f.type === FrameType.Headers)!;
    // The stream stays open for the body, so HEADERS must not end it.
    expect(headers.flags & Flags.EndStream).toBe(0);
    const payload = frames.find((f) => f.type === FrameType.Data)!;
    expect(new TextDecoder().decode(payload.payload)).toBe('{"a":1}');
    expect(payload.flags & Flags.EndStream).toBe(Flags.EndStream);
  });
});
