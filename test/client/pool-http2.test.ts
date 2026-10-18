import { describe, expect, it } from 'vitest';
import { encodeFrame, encodeSettings, FrameType, Setting } from '../../src/http/h2/frames';
import type { Dial } from '../../src/net/socket';
import { DEFAULT_PROFILE } from '../../src/http/h2/connection';
import { dataFrame, headersFrame, http2Server, on, path } from './pool-peers';

describe('a kept HTTP/2 connection', () => {
  it('carries requests made at once on one connection, each on its own stream', async () => {
    const pending: [number, string][] = [];
    const server = http2Server((stream, headers, send) => {
      pending.push([stream, path(headers)]);
      // Answer both once both have arrived, the second first.
      if (pending.length < 2) return;
      for (const [id, asked] of [...pending].reverse()) {
        send(headersFrame(id, 200));
        send(dataFrame(id, asked));
      }
    });
    const session = on(server.dial, 'h2');

    const [a, b] = await Promise.all([
      session.get('https://example.com/a'),
      session.get('https://example.com/b'),
    ]);
    expect([await a.text(), await b.text()]).toEqual(['/a', '/b']);
    expect(server.frames).toHaveLength(1);
    const streams = server.frames[0]!.filter((f) => f.type === FrameType.Headers);
    expect(streams.map((f) => f.stream)).toEqual([1, 3]);
    // The preface and SETTINGS went out once, not once per request.
    expect(
      server.frames[0]!.filter((f) => f.type === FrameType.Settings && f.flags === 0),
    ).toHaveLength(1);
  });

  it('carries the next request on the connection the last one opened', async () => {
    const server = http2Server((stream, headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, path(headers)));
    });
    const session = on(server.dial, 'h2');
    for (const p of ['/1', '/2', '/3']) {
      expect(await (await session.get(`https://example.com${p}`)).text()).toBe(p);
    }
    expect(server.frames).toHaveLength(1);
  });

  it('resets a cancelled stream and leaves the others be', async () => {
    const server = http2Server((stream, headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, path(headers), path(headers) !== '/endless'));
    });
    const session = on(server.dial, 'h2');

    const endless = await session.get('https://example.com/endless');
    await endless.body!.cancel();
    expect(await (await session.get('https://example.com/after')).text()).toBe('/after');

    const reset = server.frames[0]!.find((f) => f.type === FrameType.RstStream);
    expect(reset?.stream).toBe(1);
    expect([...reset!.payload]).toEqual([0, 0, 0, 8]); // CANCEL
    expect(server.frames).toHaveLength(1);
  });

  it('gives up on one request without closing the connection under the rest', async () => {
    const server = http2Server((stream, headers, send) => {
      if (path(headers) === '/slow') return;
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'fast'));
    });
    const session = on(server.dial, 'h2');

    const slow = session.get('https://example.com/slow', { timeoutMs: 30 });
    await expect(slow).rejects.toThrow(/took longer than 30ms/);
    expect(await (await session.get('https://example.com/fast')).text()).toBe('fast');
    expect(server.frames).toHaveLength(1);
    expect(server.closed()).toBe(0);
  });

  it('sends a request a GOAWAY left unprocessed again on a new connection', async () => {
    const server = http2Server((stream, headers, send, connection) => {
      if (connection === 0 && stream === 3) {
        // Stream 1 is finished; 3 the server never looked at.
        const goAway = new Uint8Array(8);
        new DataView(goAway.buffer).setUint32(0, 1);
        send(encodeFrame(FrameType.GoAway, 0, 0, goAway));
        return;
      }
      send(headersFrame(stream, 200));
      send(dataFrame(stream, `${connection}${path(headers)}`));
    });
    const session = on(server.dial, 'h2');
    expect(await (await session.get('https://example.com/a')).text()).toBe('0/a');
    expect(await (await session.post('https://example.com/b', { body: 'x' })).text()).toBe('1/b');
    expect(server.frames).toHaveLength(2);
  });

  it('opens a second connection once the first is at its stream limit', async () => {
    const waiting: (() => void)[] = [];
    const server = http2Server((stream, _headers, send) => {
      waiting.push(() => {
        send(headersFrame(stream, 200));
        send(dataFrame(stream, 'ok'));
      });
    });
    const limited: Dial = async (hostname, port) => {
      const socket = await server.dial(hostname, port);
      // The server allows one stream at a time.
      const reader = socket.readable.getReader();
      const readable = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            encodeFrame(
              FrameType.Settings,
              0,
              0,
              encodeSettings([[Setting.MaxConcurrentStreams, 1]]),
            ),
          );
        },
        async pull(controller) {
          const { value, done } = await reader.read();
          if (done) controller.close();
          else controller.enqueue(value);
        },
      });
      return { ...socket, readable };
    };
    const session = on(limited, 'h2');
    const first = session.get('https://example.com/1');
    // Let the first connection's SETTINGS arrive before the second request.
    await new Promise((resolve) => setTimeout(resolve, 10));
    const second = session.get('https://example.com/2');
    await new Promise((resolve) => setTimeout(resolve, 10));
    for (const answer of waiting) answer();
    await Promise.all([(await first).text(), (await second).text()]);
    expect(server.frames).toHaveLength(2);
  });
});

/** Each HEADERS frame's stream, exclusive bit, dependency and weight. */
const priorities = (
  frames: { type: number; flags: number; stream: number; payload: Uint8Array }[],
) =>
  frames
    .filter((f) => f.type === FrameType.Headers)
    .map((f) => {
      const word = new DataView(f.payload.buffer, f.payload.byteOffset).getUint32(0);
      return [f.stream, word >>> 31 === 1, word & 0x7fffffff, f.payload[4]! + 1];
    });

describe('streams as a browser numbers and chains them', () => {
  it('chains streams open at once, as Chromium does, and roots one sent after', async () => {
    const waiting: (() => void)[] = [];
    const server = http2Server((stream, _headers, send) => {
      waiting.push(() => {
        send(headersFrame(stream, 200));
        send(dataFrame(stream, 'ok'));
      });
    });
    const chromium = {
      ...DEFAULT_PROFILE,
      priority: { weight: 256, exclusive: true },
      dependOnOpen: true,
    };
    const session = on(server.dial, 'h2', { http2: chromium });

    const together = ['/a', '/b', '/c'].map((p) => session.get(`https://example.com${p}`));
    await new Promise((resolve) => setTimeout(resolve, 10));
    for (const answer of waiting.splice(0)) answer();
    for (const response of await Promise.all(together)) await response.text();
    const after = session.get('https://example.com/after');
    await new Promise((resolve) => setTimeout(resolve, 10));
    for (const answer of waiting.splice(0)) answer();
    await (await after).text();

    expect(priorities(server.frames[0]!)).toEqual([
      [1, true, 0, 256],
      [3, true, 1, 256],
      [5, true, 3, 256],
      [7, true, 0, 256],
    ]);
  });

  it('starts at stream 3 and widens each stream, as Firefox does', async () => {
    const server = http2Server((stream, _headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'ok'));
    });
    const firefox = {
      ...DEFAULT_PROFILE,
      priority: { weight: 42, exclusive: false },
      firstStream: 3,
      streamWindowUpdate: 12_451_840,
    };
    const session = on(server.dial, 'h2', { http2: firefox });
    await (await session.get('https://example.com/1')).text();
    await (await session.get('https://example.com/2')).text();

    const sent = server.frames[0]!.filter(
      (f) => f.type === FrameType.Headers || (f.type === FrameType.WindowUpdate && f.stream !== 0),
    );
    expect(sent.map((f) => [f.type, f.stream])).toEqual([
      [FrameType.Headers, 3],
      [FrameType.WindowUpdate, 3],
      [FrameType.Headers, 5],
      [FrameType.WindowUpdate, 5],
    ]);
    const increment = new DataView(sent[1]!.payload.buffer, sent[1]!.payload.byteOffset).getUint32(
      0,
    );
    expect(increment).toBe(12_451_840);
    expect(priorities(server.frames[0]!).map(([, exclusive, on]) => [exclusive, on])).toEqual([
      [false, 0],
      [false, 0],
    ]);
  });
});
