import { describe, expect, it } from 'vitest';
import { encodeFrame, encodeSettings, FrameType, Setting } from '../../src/http/h2/frames';
import type { Dial } from '../../src/net/socket';
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
