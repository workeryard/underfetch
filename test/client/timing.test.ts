import { describe, expect, it } from 'vitest';
import { timingOf } from '../../src/client/timing';
import type { Dial } from '../../src/net/socket';
import { http1Server, ok, on } from './pool-peers';

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe('timing', () => {
  it('measures connecting on a new connection and leaves it out on a kept one', async () => {
    const server = http1Server(() => ok('ok'));
    // Dialling takes 40 ms here, and nothing else does.
    const slow: Dial = async (hostname, port) => {
      await pause(40);
      return server.dial(hostname, port);
    };
    const session = on(slow);

    const first = await session.get('http://example.com/');
    const fresh = timingOf(first)!;
    expect(fresh.reused).toBe(false);
    expect(fresh.connect).toBeGreaterThanOrEqual(35);
    // Plain http, no proxy: phases that did not happen are absent, not zero.
    expect(fresh.tls).toBeUndefined();
    expect(fresh.proxy).toBeUndefined();
    expect(fresh.firstByte).toBeGreaterThanOrEqual(fresh.connect!);
    expect(fresh.total).toBeUndefined();
    await first.text();
    expect(fresh.total).toBeGreaterThanOrEqual(fresh.firstByte);

    const second = await session.get('http://example.com/');
    await second.text();
    const kept = timingOf(second)!;
    expect(kept.reused).toBe(true);
    expect(kept.connect).toBeUndefined();
    expect(kept.firstByte).toBeLessThan(35);
  });

  it('has nothing for a response that did not come over a connection of ours', () => {
    expect(timingOf(new Response('made here'))).toBeUndefined();
  });

  it('sets the total at once for an answer with no body', async () => {
    const server = http1Server(() => 'HTTP/1.1 204 No Content\r\n\r\n');
    const response = await on(server.dial).get('http://example.com/');
    const timing = timingOf(response)!;
    expect(timing.total).toBe(timing.firstByte);
  });
});
