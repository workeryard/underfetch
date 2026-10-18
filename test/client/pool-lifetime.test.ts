import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { dataFrame, headersFrame, http1Server, http2Server, ok, on } from './pool-peers';

/**
 * How long kept connections live: until the session is closed or disposed,
 * or until they have carried nothing for idleTimeoutMs.
 */

const IDLE = 1_000;

afterEach(() => {
  vi.useRealTimers();
});

/** Fake setTimeout and Date, so idleMs can pass without waiting for it. */
const fakeClock = () => vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });

describe('disposing a session', () => {
  it('closes its connections at the end of a using block', async () => {
    const server = http1Server(() => ok('ok'));
    {
      using session = on(server.dial);
      await (await session.get('http://example.com/')).text();
      expect(server.closed()).toBe(0);
    }
    await Promise.resolve();
    expect(server.closed()).toBe(1);
  });

  it('waits for the sockets to close with await using', async () => {
    const server = http2Server((stream, _headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'ok'));
    });
    {
      await using session = on(server.dial, 'h2');
      await (await session.get('https://example.com/')).text();
    }
    expect(server.closed()).toBe(1);
  });
});

describe('an idle HTTP/1.1 connection', () => {
  it('is closed after idleTimeoutMs, though no request comes again', async () => {
    fakeClock();
    const server = http1Server(() => ok('ok'));
    const session = on(server.dial, undefined, { idleTimeoutMs: IDLE });
    await (await session.get('http://example.com/')).text();

    await vi.advanceTimersByTimeAsync(IDLE - 1);
    expect(server.closed()).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(server.closed()).toBe(1);
  });

  it('is not closed when it was taken again before then', async () => {
    fakeClock();
    const server = http1Server(() => ok('ok'));
    const session = on(server.dial, undefined, { idleTimeoutMs: IDLE });
    await (await session.get('http://example.com/')).text();
    await vi.advanceTimersByTimeAsync(IDLE - 100);
    const second = await session.get('http://example.com/');

    // Carrying an answer at the old deadline, and kept.
    await vi.advanceTimersByTimeAsync(200);
    expect(server.closed()).toBe(0);
    await second.text();
    expect(server.requests).toEqual([[expect.any(String), expect.any(String)]]);
  });
});

describe('an idle HTTP/2 connection', () => {
  it('is closed after idleTimeoutMs with no stream open', async () => {
    fakeClock();
    const server = http2Server((stream, _headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'ok'));
    });
    const session = on(server.dial, 'h2', { idleTimeoutMs: IDLE });
    await (await session.get('https://example.com/')).text();

    await vi.advanceTimersByTimeAsync(IDLE - 1);
    expect(server.closed()).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(server.closed()).toBe(1);
    // The next request opens a new one rather than ride the closed one.
    await (await session.get('https://example.com/')).text();
    expect(server.frames).toHaveLength(2);
  });

  it('is not closed while a stream is open on it', async () => {
    fakeClock();
    const server = http2Server((stream, _headers, send) => {
      // Headers, and a body that never ends.
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'still', false));
    });
    const session = on(server.dial, 'h2', { idleTimeoutMs: IDLE });
    const open = await session.get('https://example.com/');

    await vi.advanceTimersByTimeAsync(IDLE * 3);
    expect(server.closed()).toBe(0);
    await open.body!.cancel();
  });
});

describe('closing a session', () => {
  it('clears its idle timers, so none fires after', async () => {
    fakeClock();
    const one = http1Server(() => ok('ok'));
    const two = http2Server((stream, _headers, send) => {
      send(headersFrame(stream, 200));
      send(dataFrame(stream, 'ok'));
    });
    const plain = on(one.dial, undefined, { idleTimeoutMs: IDLE });
    const multiplexed = on(two.dial, 'h2', { idleTimeoutMs: IDLE });
    await (await plain.get('http://example.com/')).text();
    await (await multiplexed.get('https://example.com/')).text();
    expect(vi.getTimerCount()).toBe(2);

    await Promise.all([plain.close(), multiplexed.close()]);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(IDLE * 2);
    expect([one.closed(), two.closed()]).toEqual([1, 1]);
  });
});

describe('a Node process with a kept connection', () => {
  it('exits on its own, kept up by no idle timer', async () => {
    const script = fileURLToPath(new URL('./fixtures/one-request.ts', import.meta.url));
    const started = Date.now();
    const { stdout: out } = await promisify(execFile)('npx', ['tsx', script], {
      timeout: 20_000,
    });
    expect(out.trim()).toBe('answered');
    // Its connection is idle for 60 s; the process must not wait them out.
    expect(Date.now() - started).toBeLessThan(15_000);
  }, 30_000);
});
