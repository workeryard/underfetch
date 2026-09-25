import { describe, expect, it } from 'vitest';
import { Session } from '../../src/client/session';
import { DialError, type Dial } from '../../src/net/socket';

const refusedForGood: Dial = () => Promise.reject(new DialError('blocked', true));
const refusedForNow: Dial = () => Promise.reject(new DialError('reset'));
const tls = () => {
  throw new Error('never reached');
};

function fallback() {
  const seen: { url: string; method: string; body: string }[] = [];
  const send = async (request: Request) => {
    seen.push({ url: request.url, method: request.method, body: await request.text() });
    return new Response('from the fallback', { status: 200, headers: { 'x-origin': 'yes' } });
  };
  return { send, seen };
}

describe('Session fallback', () => {
  it('sends a request refused for good through the fallback, and marks the answer', async () => {
    const via = fallback();
    const session = new Session({ dial: refusedForGood, tls, fallback: via.send, retry: false });

    const response = await session.post('https://example.com/api', { json: { a: 1 } });

    expect(await response.text()).toBe('from the fallback');
    expect(response.headers.get('x-underfetch-via')).toBe('fallback');
    expect(response.headers.get('x-origin')).toBe('yes');
    expect(via.seen).toEqual([{ url: 'https://example.com/api', method: 'POST', body: '{"a":1}' }]);
  });

  it('leaves a refusal that may pass to the retries, not the fallback', async () => {
    const via = fallback();
    const session = new Session({ dial: refusedForNow, tls, fallback: via.send, retry: false });
    await expect(session.get('https://example.com/')).rejects.toThrow(/reset/);
    expect(via.seen).toHaveLength(0);
  });

  it('never uses the fallback through a proxy, which is the way around the block', async () => {
    const via = fallback();
    const session = new Session({
      dial: refusedForGood,
      tls,
      fallback: via.send,
      retry: false,
      proxy: { kind: 'socks5', hostname: 'p', port: 1080 },
    });
    await expect(session.get('https://example.com/')).rejects.toThrow(/blocked/);
    expect(via.seen).toHaveLength(0);
  });

  it('fails as before without a fallback', async () => {
    const session = new Session({ dial: refusedForGood, tls, retry: false });
    await expect(session.get('https://example.com/')).rejects.toThrow(DialError);
  });
});
