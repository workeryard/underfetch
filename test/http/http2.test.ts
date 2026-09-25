import { describe, expect, it } from 'vitest';
import { Hpack } from '../../src/http/h2/hpack';
import { http2Fetch, DEFAULT_PROFILE } from '../../src/http/h2/connection';
import {
  decodeSettings,
  encodeFrame,
  Flags,
  FrameType,
  Http2Error,
  PREFACE,
  Setting,
} from '../../src/http/h2/frames';
import { data, framesIn, OK, serverHeaders, SETTINGS, socketOf } from './h2-peer';

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

  it('sends a body in frames and waits for the server to open its window', async () => {
    const update = (stream: number, increment: number) => {
      const payload = new Uint8Array(4);
      new DataView(payload.buffer).setUint32(0, increment);
      return encodeFrame(FrameType.WindowUpdate, 0, stream, payload);
    };
    // The default 65,535-byte window, then room for the rest on both levels.
    const { socket, written } = socketOf([
      SETTINGS,
      update(0, 100_000),
      update(1, 100_000),
      OK,
      data('{}'),
    ]);
    const body = new Uint8Array(150_000).fill(7);
    await (
      await http2Fetch(socket, new Request('https://example.com/', { method: 'POST', body }))
    ).text();

    const sent = framesIn(written).filter((f) => f.type === FrameType.Data);
    expect(sent.every((f) => f.payload.length <= 16_384)).toBe(true);
    expect(sent.reduce((n, f) => n + f.payload.length, 0)).toBe(150_000);
    expect(sent.filter((f) => (f.flags & Flags.EndStream) !== 0)).toHaveLength(1);
    expect(sent.at(-1)!.flags & Flags.EndStream).toBe(Flags.EndStream);
  });

  it('stops sending a body the server has already answered', async () => {
    const refused = serverHeaders([[':status', '413']], Flags.EndStream);
    const { socket, written } = socketOf([SETTINGS, refused]);
    const body = new Uint8Array(200_000);
    const response = await http2Fetch(
      socket,
      new Request('https://example.com/', { method: 'POST', body }),
    );

    expect(response.status).toBe(413);
    const sent = framesIn(written).filter((f) => f.type === FrameType.Data);
    expect(sent.reduce((n, f) => n + f.payload.length, 0)).toBe(65_535);
  });

  it('opens the window before a small one runs dry', async () => {
    const small = {
      ...DEFAULT_PROFILE,
      settings: [[Setting.InitialWindowSize, 131_072]] as [number, number][],
    };
    const chunk = 'x'.repeat(16_384);
    const { socket, written } = socketOf([
      SETTINGS,
      OK,
      ...Array.from({ length: 5 }, () => data(chunk, false)),
      data(''),
    ]);
    await (await http2Fetch(socket, new Request('https://example.com/'), small)).text();

    // 80 KB read against a 128 KB window: past half, so it must be topped up.
    const updates = framesIn(written).filter(
      (f) => f.type === FrameType.WindowUpdate && f.stream === 1,
    );
    expect(updates.length).toBeGreaterThan(0);
  });

  it('puts the profile priority on HEADERS, and none when it has none', async () => {
    const send = async (priority?: { weight: number; exclusive: boolean }) => {
      const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
      const profile = { ...DEFAULT_PROFILE, priority };
      await (await http2Fetch(socket, new Request('https://example.com/'), profile)).text();
      return framesIn(written).find((f) => f.type === FrameType.Headers)!;
    };

    const chrome = await send({ weight: 256, exclusive: true });
    expect(chrome.flags & Flags.Priority).toBe(Flags.Priority);
    expect([...chrome.payload.subarray(0, 5)]).toEqual([0x80, 0, 0, 0, 255]);
    // The header block still decodes once the priority is stepped over.
    expect(new Hpack().decode(chrome.payload.subarray(5))[0]).toEqual([':method', 'GET']);

    const firefox = await send({ weight: 42, exclusive: false });
    expect([...firefox.payload.subarray(0, 5)]).toEqual([0, 0, 0, 0, 41]);

    const safari = await send(undefined);
    expect(safari.flags & Flags.Priority).toBe(0);
  });
});
