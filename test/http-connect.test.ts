import { describe, expect, it } from 'vitest';
import { httpConnect, HttpConnectError } from '../src/http-connect';
import type { ByteSocket } from '../src/socket';

function fakeProxy(answer: string): { socket: ByteSocket; sent: () => string } {
  const written: number[] = [];
  const socket: ByteSocket = {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(answer));
        controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>({
      write(chunk) {
        written.push(...chunk);
      },
    }),
    close: () => Promise.resolve(),
  };
  return { socket, sent: () => new TextDecoder().decode(new Uint8Array(written)) };
}

const PROXY = { kind: 'http', hostname: 'p', port: 8080 } as const;

const text = async (stream: ReadableStream<Uint8Array>) =>
  new TextDecoder().decode((await stream.getReader().read()).value);

describe('http connect', () => {
  it('asks for the target and hands back what follows the blank line', async () => {
    const { socket, sent } = fakeProxy(
      'HTTP/1.1 200 Connection Established\r\nProxy-Agent: t\r\n\r\nhello',
    );

    const tunnel = await httpConnect(socket, PROXY, 'api.groq.com', 443);

    expect(sent()).toContain('CONNECT api.groq.com:443 HTTP/1.1\r\n');
    expect(sent()).toContain('Host: api.groq.com:443\r\n');
    expect(sent()).not.toContain('Proxy-Authorization');
    // The proxy's own headers are consumed; only the target's bytes remain.
    expect(await text(tunnel.readable)).toBe('hello');
  });

  it('sends basic credentials when it has them', async () => {
    const { socket, sent } = fakeProxy('HTTP/1.1 200 OK\r\n\r\n');

    await httpConnect(
      socket,
      { ...PROXY, username: 'ada', password: 'lovelace' },
      'example.com',
      443,
    );

    expect(sent()).toContain(`Proxy-Authorization: Basic ${btoa('ada:lovelace')}\r\n`);
  });

  it('names a rejected password rather than a bare status', async () => {
    const { socket } = fakeProxy('HTTP/1.1 407 Proxy Authentication Required\r\n\r\n');
    await expect(httpConnect(socket, PROXY, 'example.com', 443)).rejects.toThrow(
      /requires authentication/,
    );
  });

  it('reports a refusal with the reason the proxy gave', async () => {
    const { socket } = fakeProxy('HTTP/1.1 403 Forbidden\r\n\r\n');
    await expect(httpConnect(socket, PROXY, 'example.com', 443)).rejects.toThrow(/403 Forbidden/);
  });

  it('refuses something that is not an HTTP proxy', async () => {
    const { socket } = fakeProxy('\x05\x00\r\n\r\n');
    await expect(httpConnect(socket, PROXY, 'example.com', 443)).rejects.toThrow(HttpConnectError);
  });
});
