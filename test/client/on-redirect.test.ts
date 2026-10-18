import { describe, expect, it } from 'vitest';
import { followRedirects, type RedirectHop } from '../../src/client/redirects';

/** A server that redirects along `chain`, then answers 200. */
function chain(...steps: [status: number, location: string][]) {
  const sent: string[] = [];
  const send = (request: Request) => {
    sent.push(`${request.method} ${request.url}`);
    const step = steps[sent.length - 1];
    return Promise.resolve(
      step === undefined
        ? new Response('arrived')
        : new Response('moved', {
            status: step[0],
            headers: { location: step[1], 'set-cookie': `hop=${sent.length}` },
          }),
    );
  };
  return { send, sent };
}

describe('onRedirect', () => {
  it('sees each hop before it is followed', async () => {
    const server = chain([302, '/b'], [303, 'http://other.example/c']);
    const hops: RedirectHop[] = [];
    const response = await followRedirects(
      new Request('https://example.com/a', { method: 'POST', body: 'x' }),
      server.send,
      { onRedirect: (hop) => void hops.push(hop) },
    );

    expect(await response.text()).toBe('arrived');
    expect(hops.map((h) => [h.hop, h.status, h.from.href, h.to.href, h.method])).toEqual([
      [1, 302, 'https://example.com/a', 'https://example.com/b', 'GET'],
      [2, 303, 'https://example.com/b', 'http://other.example/c', 'GET'],
    ]);
    expect(hops.map((h) => [h.crossOrigin, h.downgrade])).toEqual([
      [false, false],
      [true, true],
    ]);
    // The 3xx's own headers, which the final answer does not carry.
    expect(hops[0]!.headers.get('set-cookie')).toBe('hop=1');
  });

  it('stops on false, before anything goes to where the hop points', async () => {
    const server = chain([302, 'https://evil.example/']);
    const response = await followRedirects(new Request('https://example.com/'), server.send, {
      onRedirect: (hop) => hop.to.origin === 'https://example.com',
    });

    expect(response.status).toBe(302);
    expect(response.url).toBe('https://example.com/');
    // Its body is still there to read.
    expect(await response.text()).toBe('moved');
    expect(server.sent).toEqual(['GET https://example.com/']);
  });

  it('fails with what the hook threw', async () => {
    const server = chain([301, '/next']);
    const refusal = new Error('not there');
    await expect(
      followRedirects(new Request('https://example.com/'), server.send, {
        onRedirect: () => {
          throw refusal;
        },
      }),
    ).rejects.toBe(refusal);
  });

  it('is not asked about a hop past the limit, which still fails', async () => {
    const server = chain([302, '/1'], [302, '/2']);
    let asked = 0;
    await expect(
      followRedirects(new Request('https://example.com/'), server.send, {
        maxRedirects: 1,
        onRedirect: () => void asked++,
      }),
    ).rejects.toThrow(/gave up after 1 redirects/);
    expect(asked).toBe(1);
  });

  it('may answer asynchronously', async () => {
    const server = chain([302, '/b']);
    const response = await followRedirects(new Request('https://example.com/'), server.send, {
      onRedirect: async () => {
        await Promise.resolve();
        return false;
      },
    });
    expect(response.status).toBe(302);
  });
});
