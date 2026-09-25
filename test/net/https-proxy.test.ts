import { describe, expect, it } from 'vitest';
import { fetchOver } from '../../src/client/fetch';
import type { ByteSocket, Dial } from '../../src/net/socket';
import type { TlsFactory, TlsSession } from '../../src/tls/tunnel';

/** A stand-in for TLS that XORs every byte with a key named for the host. */
const keyOf = (hostname: string) => hostname.length & 0xff;
const xor = (data: Uint8Array, key: number) => data.map((b) => b ^ key);

class XorTls implements TlsSession {
  handshaking = false;
  protocol = undefined;
  #plain: number[] = [];
  #out: number[] = [];
  constructor(readonly key: number) {}
  receive(data: Uint8Array): number {
    this.#plain.push(...xor(data, this.key));
    return data.length;
  }
  outgoing(): Uint8Array {
    const out = new Uint8Array(this.#out);
    this.#out = [];
    return out;
  }
  send(data: Uint8Array): void {
    this.#out.push(...xor(data, this.key));
  }
  plaintext(): Uint8Array {
    const plain = new Uint8Array(this.#plain);
    this.#plain = [];
    return plain;
  }
  close(): void {}
}

/**
 * An HTTPS proxy and the target behind it, in one. The proxy's layer is
 * undone first; after its 200, what arrives is also under the target's.
 */
function httpsProxy(proxyHost: string, targetHost: string) {
  const outer = keyOf(proxyHost);
  const both = outer ^ keyOf(targetHost);
  const seen = { connect: '', request: '' };
  let push: (bytes: Uint8Array) => void = () => undefined;
  const dial: Dial = () => {
    let text = '';
    let tunnelled = false;
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          push = (bytes) => controller.enqueue(bytes);
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          text += new TextDecoder().decode(xor(chunk, tunnelled ? both : outer));
          if (!tunnelled && text.endsWith('\r\n\r\n')) {
            seen.connect = text;
            text = '';
            tunnelled = true;
            push(
              xor(new TextEncoder().encode('HTTP/1.1 200 Connection Established\r\n\r\n'), outer),
            );
          } else if (tunnelled && text.includes('\r\n\r\n')) {
            seen.request = text;
            push(
              xor(
                new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\ninside'),
                both,
              ),
            );
          }
        },
      }),
      close: () => Promise.resolve(),
    };
    return Promise.resolve(socket);
  };
  return { dial, seen };
}

describe('HTTPS proxy', () => {
  it('runs the target TLS inside TLS to the proxy', async () => {
    const wire = httpsProxy('proxy.example', 'api.target.example');
    const made: [string, string | undefined][] = [];
    const tls: TlsFactory = (hostname, alpn) => {
      made.push([hostname, alpn]);
      return new XorTls(keyOf(hostname));
    };

    const response = await fetchOver(new Request('https://api.target.example/v1'), {
      dial: wire.dial,
      tls,
      proxy: { kind: 'https', hostname: 'proxy.example', port: 443, username: 'u', password: 'p' },
    });

    expect(await response.text()).toBe('inside');
    // The proxy's certificate is checked against its own name, and first.
    expect(made).toEqual([
      ['proxy.example', 'http/1.1'],
      ['api.target.example', undefined],
    ]);
    expect(wire.seen.connect).toContain('CONNECT api.target.example:443 HTTP/1.1');
    expect(wire.seen.connect).toContain(`Proxy-Authorization: Basic ${btoa('u:p')}`);
    expect(wire.seen.request).toMatch(/^GET \/v1 HTTP\/1.1\r\nHost: api.target.example/);
  });
});
