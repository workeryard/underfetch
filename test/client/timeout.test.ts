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
