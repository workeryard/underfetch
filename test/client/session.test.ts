import { describe, expect, it } from 'vitest';
import { Session } from '../../src/client/session';
import type { ByteSocket, Dial } from '../../src/net/socket';
import type { TlsSession } from '../../src/tls/tunnel';

class Passthrough implements TlsSession {
  handshaking = false;
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
const ANSWER = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok';
const PROXY = { kind: 'socks5', hostname: '203.0.113.7', port: 1080 } as const;

/** Records every address dialled and what was written to each socket. */
function net(withHandshake: boolean) {
  const dialled: string[] = [];
  const sent: string[] = [];
  const dial: Dial = (hostname, port) => {
    dialled.push(`${hostname}:${port}`);
    const written: number[] = [];
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          if (withHandshake) controller.enqueue(new Uint8Array([...OPEN, ...GRANTED]));
          controller.enqueue(new TextEncoder().encode(ANSWER));
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
      close: () => {
        sent.push(new TextDecoder().decode(new Uint8Array(written)));
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, dialled, sent };
}

const options = (wire: ReturnType<typeof net>) => ({
  dial: wire.dial,
  tls: () => new Passthrough(),
});

describe('Session', () => {
  it('goes straight to the target when it has no proxy', async () => {
    const wire = net(false);
    const session = new Session(options(wire));

    const response = await session.fetch('https://api.groq.com/v1/models');

    expect(wire.dialled).toEqual(['api.groq.com:443']);
    expect(await response.text()).toBe('ok');
  });

  it('remembers a proxy across requests', async () => {
    const wire = net(true);
    const session = new Session({ ...options(wire), proxy: PROXY });

    await session.fetch('https://a.example/');
    await session.fetch('https://b.example/');

    expect(wire.dialled).toEqual(['203.0.113.7:1080', '203.0.113.7:1080']);
    expect(session.proxy).toBe(PROXY);
  });

  it('lets one request opt out of the session proxy', async () => {
    const wire = net(false);
    const session = new Session({ ...options(wire), proxy: PROXY });

    await session.fetch('https://direct.example/', { proxy: null });

    expect(wire.dialled).toEqual(['direct.example:443']);
  });

  it('adds its own headers without overwriting the request', async () => {
    const wire = net(false);
    const session = new Session({
      ...options(wire),
      headers: { 'user-agent': 'session-agent', 'x-from': 'session' },
    });

    const response = await session.fetch('https://example.com/', {
      headers: { 'user-agent': 'request-agent' },
    });
    await response.text();

    const wireText = wire.sent[0] ?? '';
    expect(wireText).toContain('user-agent: request-agent');
    expect(wireText).not.toContain('session-agent');
    expect(wireText).toContain('x-from: session');
  });
});
