import { describe, expect, it } from 'vitest';
import { socks5Connect, Socks5Error } from '../src/socks5';
import type { ByteSocket } from '../src/socket';

/**
 * The client's side of the conversation never branches on timing, so a test can
 * queue the whole of the proxy's answer up front and read back what was sent.
 */
function fakeProxy(answer: number[]): { socket: ByteSocket; sent: number[] } {
  const sent: number[] = [];
  const socket: ByteSocket = {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(answer));
        controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>({
      write(chunk) {
        sent.push(...chunk);
      },
    }),
    close: () => Promise.resolve(),
  };
  return { socket, sent };
}

/** A successful CONNECT reply bound to 0.0.0.0:0. */
const GRANTED = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
const OPEN = [0x05, 0x00];

const text = async (stream: ReadableStream<Uint8Array>) =>
  new TextDecoder().decode((await stream.getReader().read()).value);

describe('socks5', () => {
  it('greets, asks for the target by name, and hands back the tunnel', async () => {
    const hello = [...new TextEncoder().encode('hello')];
    const { socket, sent } = fakeProxy([...OPEN, ...GRANTED, ...hello]);

    const tunnel = await socks5Connect(socket, { kind: 'socks5', hostname: 'p', port: 1080 }, 'api.groq.com', 443);

    // Greeting: version 5, one method, "no authentication".
    expect(sent.slice(0, 3)).toEqual([0x05, 0x01, 0x00]);
    // CONNECT, reserved, address type 3 (a domain), then the length-prefixed name.
    expect(sent.slice(3, 8)).toEqual([0x05, 0x01, 0x00, 0x03, 'api.groq.com'.length]);
    expect(String.fromCharCode(...sent.slice(8, 8 + 12))).toBe('api.groq.com');
    // The port, big-endian.
    expect(sent.slice(-2)).toEqual([0x01, 0xbb]);
    // Whatever the target already said survives the handshake.
    expect(await text(tunnel.readable)).toBe('hello');
  });

  it('sends a username and password when the proxy asks for them', async () => {
    const { socket, sent } = fakeProxy([0x05, 0x02, 0x01, 0x00, ...GRANTED]);

    await socks5Connect(
      socket,
      { kind: 'socks5', hostname: 'p', port: 1080, username: 'ada', password: 'lovelace' },
      'example.com',
      443,
    );

    // Both methods are offered, password first.
    expect(sent.slice(0, 4)).toEqual([0x05, 0x02, 0x02, 0x00]);
    // RFC 1929: version 1, then each credential length-prefixed.
    const auth = sent.slice(4, 4 + 3 + 3 + 8);
    expect(auth.slice(0, 2)).toEqual([0x01, 3]);
    expect(String.fromCharCode(...auth.slice(2, 5))).toBe('ada');
    expect(auth[5]).toBe(8);
    expect(String.fromCharCode(...auth.slice(6, 14))).toBe('lovelace');
  });

  it('reads past a bound address of any type', async () => {
    const ipv6Reply = [0x05, 0x00, 0x00, 0x04, ...Array<number>(16).fill(0), 0x1f, 0x90];
    const body = [...new TextEncoder().encode('body')];
    const { socket } = fakeProxy([...OPEN, ...ipv6Reply, ...body]);

    const tunnel = await socks5Connect(socket, { kind: 'socks5', hostname: 'p', port: 1080 }, 'example.com', 443);
    expect(await text(tunnel.readable)).toBe('body');
  });

  it('explains why the proxy refused', async () => {
    const refused = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    const { socket } = fakeProxy([...OPEN, ...refused]);

    await expect(
      socks5Connect(socket, { kind: 'socks5', hostname: 'p', port: 1080 }, 'example.com', 443),
    ).rejects.toThrow(/connection refused/);
  });

  it('refuses a proxy that wants an authentication we cannot give', async () => {
    const { socket } = fakeProxy([0x05, 0xff]);
    await expect(
      socks5Connect(socket, { kind: 'socks5', hostname: 'p', port: 1080 }, 'example.com', 443),
    ).rejects.toThrow(/requires authentication/);
  });

  it('reports a rejected password rather than hanging on the next read', async () => {
    const { socket } = fakeProxy([0x05, 0x02, 0x01, 0x01]);
    await expect(
      socks5Connect(
        socket,
        { kind: 'socks5', hostname: 'p', port: 1080, username: 'ada', password: 'wrong' },
        'example.com',
        443,
      ),
    ).rejects.toThrow(Socks5Error);
  });

  it('refuses to talk to something that is not a SOCKS5 proxy', async () => {
    const { socket } = fakeProxy([0x04, 0x00]);
    await expect(
      socks5Connect(socket, { kind: 'socks5', hostname: 'p', port: 1080 }, 'example.com', 443),
    ).rejects.toThrow(/SOCKS version 4/);
  });
});
