import { describe, expect, it } from 'vitest';
import { http1Server, ok, on } from './pool-peers';

describe('a kept HTTP/1.1 connection', () => {
  it('carries one request after another, each written in full', async () => {
    const server = http1Server((request) => ok(request.split(' ')[1]!));
    const session = on(server.dial);

    for (const path of ['/a', '/b', '/c']) {
      expect(await (await session.get(`http://example.com${path}`)).text()).toBe(path);
    }
    expect(server.requests).toHaveLength(1);
    expect(server.requests[0]!.map((r) => r.split('\r\n')[0])).toEqual([
      'GET /a HTTP/1.1',
      'GET /b HTTP/1.1',
      'GET /c HTTP/1.1',
    ]);
  });

  it('is not shared between hosts, or with a different proxy', async () => {
    const server = http1Server(() => ok('ok'));
    const session = on(server.dial);
    await (await session.get('http://one.example/')).text();
    await (await session.get('http://two.example/')).text();
    await (await session.get('http://one.example/')).text();
    expect(server.requests.map((r) => r.length)).toEqual([2, 1]);
  });

  it('is let go when the server says it will close', async () => {
    const server = http1Server(() => ok('ok', 'Connection: close\r\n'));
    const session = on(server.dial);
    await (await session.get('http://example.com/')).text();
    await (await session.get('http://example.com/')).text();
    expect(server.requests).toHaveLength(2);
    expect(server.closed()).toBe(2);
  });

  it('is not used again while its answer is still coming, or once that was cut off', async () => {
    // The first answer promises more than it sends: its body is still coming.
    const server = http1Server((_request, connection) =>
      connection === 0 ? 'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial' : ok('ok'),
    );
    const session = on(server.dial);
    const first = await session.get('http://example.com/');
    await (await session.get('http://example.com/')).text();
    expect(server.requests).toHaveLength(2);

    await first.body!.cancel();
    await (await session.get('http://example.com/')).text();
    // The cut-off one was closed; the one read to its end went on.
    expect(server.requests.map((r) => r.length)).toEqual([1, 2]);
    expect(server.closed()).toBe(1);
  });

  it('sends a request again on a new one when the server had hung up on it', async () => {
    let answered = 0;
    const server = http1Server((request, connection) => {
      // The first connection answers once, then hangs up while idle.
      if (connection === 0 && answered++ > 0) return null;
      return ok(request.endsWith('{"a":1}') ? 'body' : 'none');
    });
    const session = on(server.dial);
    await (await session.get('http://example.com/')).text();

    const response = await session.post('http://example.com/', { body: '{"a":1}' });
    // The POST was never acted on, so it was safe to send again, body and all.
    expect(await response.text()).toBe('body');
    expect(server.requests).toHaveLength(2);
  });

  it('closes each connection with its answer when keepAlive is off', async () => {
    const server = http1Server(() => ok('ok'));
    const session = on(server.dial, undefined, { keepAlive: false });
    await (await session.get('http://example.com/')).text();
    await (await session.get('http://example.com/')).text();
    expect(server.requests).toHaveLength(2);
    expect(server.closed()).toBe(2);
  });

  it('closes what it keeps on close(), and what is still answering', async () => {
    const server = http1Server((request) =>
      request.startsWith('GET /slow')
        ? 'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial'
        : ok('ok'),
    );
    const session = on(server.dial);
    await (await session.get('http://example.com/')).text();
    const slow = await session.get('http://other.example/slow');
    expect(server.closed()).toBe(0);

    session.close();
    expect(server.closed()).toBe(2);
    await expect(slow.text()).rejects.toThrow();
    // Nothing comes back to the pool once it has been closed.
    await (await session.get('http://other.example/')).text();
    expect(server.requests).toHaveLength(3);
  });
});
