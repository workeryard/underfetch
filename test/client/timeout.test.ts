import { describe, expect, it } from 'vitest';
import { TimeoutError } from '../../src/client/abort';
import { proxyFetch } from '../../src/client/fetch';
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

const PROXY = { kind: 'socks5', hostname: 'p', port: 1080 } as const;

/** A proxy that accepts the connection and then says nothing, ever. */
function silent(): { dial: Dial; closed: () => boolean } {
  let closed = false;
  const dial: Dial = () => {
    const socket: ByteSocket = {
      // Never enqueues and never closes: the read simply never returns.
      readable: new ReadableStream<Uint8Array>({}),
      writable: new WritableStream<Uint8Array>(),
      close: () => {
        closed = true;
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, closed: () => closed };
}

describe('giving up', () => {
  it('stops waiting on a proxy that never answers', async () => {
    const net = silent();
    const started = Date.now();

    await expect(
      proxyFetch(new Request('https://example.com/'), {
        dial: net.dial,
        tls: () => new Passthrough(),
        proxy: PROXY,
        timeoutMs: 120,
      }),
    ).rejects.toThrow(TimeoutError);

    expect(Date.now() - started).toBeLessThan(2_000);
    // The socket must not be left open: nothing else would ever close it.
    expect(net.closed()).toBe(true);
  });

  it('obeys a signal the caller already aborted', async () => {
    const net = silent();
    await expect(
      proxyFetch(new Request('https://example.com/'), {
        dial: net.dial,
        tls: () => new Passthrough(),
        proxy: PROXY,
        signal: AbortSignal.abort(new Error('changed my mind')),
      }),
    ).rejects.toThrow(/changed my mind/);
  });

  it('aborts partway through the handshake', async () => {
    const net = silent();
    const controller = new AbortController();
    const pending = proxyFetch(new Request('https://example.com/'), {
      dial: net.dial,
      tls: () => new Passthrough(),
      proxy: PROXY,
      signal: controller.signal,
    });

    controller.abort(new Error('caller left'));
    await expect(pending).rejects.toThrow(/caller left/);
    expect(net.closed()).toBe(true);
  });
});

describe('connect timeout', () => {
  it('gives up on a proxy that never answers, long before the request would', async () => {
    const net = silent();
    const started = Date.now();
    const error = await proxyFetch(new Request('https://example.com/'), {
      dial: net.dial,
      tls: () => new Passthrough(),
      proxy: PROXY,
      timeoutMs: 10_000,
      connectTimeoutMs: 50,
    }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TimeoutError);
    expect(String(error)).toMatch(/connecting took longer than 50ms/);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(net.closed()).toBe(true);
  });

  it('gives up on a dial that never completes', async () => {
    const hanging: Dial = () => new Promise(() => undefined);
    await expect(
      proxyFetch(new Request('https://example.com/'), {
        dial: hanging,
        tls: () => new Passthrough(),
        connectTimeoutMs: 50,
      }),
    ).rejects.toThrow(/connecting took longer/);
  });

  it('leaves a slow answer alone once connected', async () => {
    let push: (text: string) => void = () => undefined;
    let end: () => void = () => undefined;
    const dial: Dial = () =>
      Promise.resolve({
        readable: new ReadableStream<Uint8Array>({
          start(controller) {
            push = (text) => controller.enqueue(new TextEncoder().encode(text));
            end = () => controller.close();
          },
        }),
        writable: new WritableStream<Uint8Array>(),
        close: () => Promise.resolve(),
      });

    const pending = proxyFetch(new Request('http://example.com/'), {
      dial,
      tls: () => new Passthrough(),
      connectTimeoutMs: 30,
    });
    // Connected at once; the server takes far longer than 30 ms to answer.
    await new Promise((resolve) => setTimeout(resolve, 120));
    push('HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow');
    end();

    const response = await pending;
    expect(await response.text()).toBe('slow');
  });
});
