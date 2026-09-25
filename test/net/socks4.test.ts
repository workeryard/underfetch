import { describe, expect, it } from 'vitest';
import { socks4Connect, Socks4Error, socks4Request } from '../../src/net/socks4';
import type { ByteSocket } from '../../src/net/socket';

function fakeProxy(answer: number[]): { socket: ByteSocket; sent: () => number[] } {
  const written: number[] = [];
  const socket: ByteSocket = {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(answer));
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
  return { socket, sent: () => written };
}

const PROXY = { kind: 'socks4', hostname: 'p', port: 1080 } as const;
const GRANTED = [0x00, 0x5a, 0, 0, 0, 0, 0, 0];
const bytes = (text: string) => [...new TextEncoder().encode(text)];

describe('socks4', () => {
  it('names the target, 4a style, so the proxy resolves it', () => {
    expect([...socks4Request('example.com', 443, 'ada')]).toEqual([
      0x04,
      0x01,
      0x01,
      0xbb,
      0,
      0,
      0,
      1,
      ...bytes('ada'),
      0,
      ...bytes('example.com'),
      0,
    ]);
  });

  it('sends an IPv4 address as itself', () => {
    expect([...socks4Request('203.0.113.7', 80)]).toEqual([
      0x04, 0x01, 0x00, 0x50, 203, 0, 113, 7, 0,
    ]);
  });

  it('refuses IPv6, which SOCKS4 cannot carry', () => {
    expect(() => socks4Request('2001:db8::1', 443)).toThrow(Socks4Error);
  });

  it('hands back what follows the reply', async () => {
    const { socket } = fakeProxy([...GRANTED, ...bytes('hello')]);
    const tunnel = await socks4Connect(socket, PROXY, 'example.com', 443);
    const { value } = await tunnel.readable.getReader().read();
    expect(new TextDecoder().decode(value)).toBe('hello');
  });

  it('says why the proxy refused', async () => {
    const { socket } = fakeProxy([0x00, 0x5d, 0, 0, 0, 0, 0, 0]);
    await expect(socks4Connect(socket, PROXY, 'example.com', 443)).rejects.toThrow(/identd/);
  });
});
