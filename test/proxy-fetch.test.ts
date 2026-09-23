import { describe, expect, it } from 'vitest';
import { proxyFetch } from '../src/index';
import type { ByteSocket, Dial } from '../src/socket';
import type { TlsSession } from '../src/tls';

/** TLS that encrypts nothing, so a test can script the wire in plain bytes. */
class Passthrough implements TlsSession {
  handshaking = false;
  hostname = '';
  #plain: number[] = [];
  #out: number[] = [];
  receive(data: Uint8Array): number {
    this.#plain.push(...data);
    return data.length;
  }
  outgoing(): Uint8Array {
    const out = new Uint8Array(this.#out);
    this.#out = [];
    return out;
  }
  send(data: Uint8Array): void {
    this.#out.push(...data);
  }
  plaintext(): Uint8Array {
    const plain = new Uint8Array(this.#plain);
    this.#plain = [];
    return plain;
  }
  close(): void {}
}

const GRANTED = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const OPEN = [0x05, 0x00];

interface Wire {
  dial: Dial;
  sent: number[];
  dialled: { hostname: string; port: number }[];
  closed: () => boolean;
}

function wire(answer: string): Wire {
  const sent: number[] = [];
  const dialled: { hostname: string; port: number }[] = [];
  let closed = false;
  const dial: Dial = (hostname, port) => {
    dialled.push({ hostname, port });
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array([...OPEN, ...GRANTED]));
          controller.enqueue(new TextEncoder().encode(answer));
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          sent.push(...chunk);
        },
      }),
      close: () => {
        closed = true;
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, sent, dialled, closed: () => closed };
}

const PROXY = { kind: 'socks5', hostname: '203.0.113.7', port: 1080 } as const;
const ANSWER = 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone';

describe('proxyFetch', () => {
  it('dials the proxy, not the target, and still asks for the target', async () => {
    const net = wire(ANSWER);
    const tls = new Passthrough();

    const response = await proxyFetch(
      new Request('https://api.groq.com/openai/v1/models', {
        headers: { authorization: 'Bearer gsk' },
      }),
      { dial: net.dial, tls: () => tls, proxy: PROXY },
    );

    // The only address we opened is the proxy's.
    expect(net.dialled).toEqual([{ hostname: '203.0.113.7', port: 1080 }]);
    const wireText = new TextDecoder().decode(new Uint8Array(net.sent));
    // The proxy is asked for the target by name, and the request follows.
    expect(wireText).toContain('api.groq.com');
    expect(wireText).toContain('GET /openai/v1/models HTTP/1.1');
    expect(wireText).toContain('authorization: Bearer gsk');
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('done');
  });

  it('checks the certificate against the target, never the proxy', async () => {
    const net = wire(ANSWER);
    const asked: string[] = [];

    await proxyFetch(new Request('https://api.openai.com/v1/models'), {
      dial: net.dial,
      tls: (hostname) => {
        asked.push(hostname);
        return new Passthrough();
      },
      proxy: PROXY,
    });

    expect(asked).toEqual(['api.openai.com']);
  });

  it('closes the tunnel only once the body has been read', async () => {
    const net = wire(ANSWER);
    const response = await proxyFetch(new Request('https://example.com/'), {
      dial: net.dial,
      tls: () => new Passthrough(),
      proxy: PROXY,
    });

    expect(net.closed()).toBe(false);
    expect(await response.text()).toBe('done');
    expect(net.closed()).toBe(true);
  });

  it('closes the tunnel when the proxy refuses', async () => {
    const sent: number[] = [];
    let closed = false;
    const dial: Dial = () => {
      const socket: ByteSocket = {
        readable: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array([...OPEN, 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            controller.close();
          },
        }),
        writable: new WritableStream<Uint8Array>({
          write: (chunk) => void sent.push(...chunk),
        }),
        close: () => {
          closed = true;
          return Promise.resolve();
        },
      };
      return Promise.resolve(socket);
    };

    await expect(
      proxyFetch(new Request('https://example.com/'), {
        dial,
        tls: () => new Passthrough(),
        proxy: PROXY,
      }),
    ).rejects.toThrow(/not allowed by ruleset/);
    expect(closed).toBe(true);
  });
});
