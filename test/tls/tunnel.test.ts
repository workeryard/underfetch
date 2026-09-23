import { describe, expect, it } from 'vitest';
import { tlsTunnel, TlsError, type TlsSession } from '../../src/tls/tunnel';
import type { ByteSocket } from '../../src/net/socket';

/**
 * A stand-in for the real session that "encrypts" by prefixing a byte. It is
 * only here to prove the pump: that every byte reaches the session, that a
 * record split across reads is not lost, and that nothing is enqueued early.
 */
class FakeSession implements TlsSession {
  handshaking = true;
  readonly taken: number[] = [];
  #plain: number[] = [];
  #out: number[] = [];
  closed = false;

  constructor(
    private readonly handshakeReplies = 1,
    /** Unread plaintext past which it refuses to read, as rustls does. */
    private readonly plainLimit = Infinity,
    /** Unsent bytes past which it refuses a write, as rustls does. */
    private readonly sendLimit = Infinity,
  ) {}

  receive(data: Uint8Array): number {
    if (this.#plain.length > this.plainLimit) throw new Error('received plaintext buffer full');
    // Takes at most two bytes a call, which is what a real session may do.
    const slice = data.subarray(0, 2);
    this.taken.push(...slice);
    if (this.handshaking) {
      if (this.taken.length >= this.handshakeReplies) this.handshaking = false;
    } else {
      this.#plain.push(...slice);
    }
    return slice.length;
  }
  outgoing(): Uint8Array {
    const out = new Uint8Array(this.#out);
    this.#out = [];
    return out;
  }
  send(data: Uint8Array): void {
    if (this.#out.length + data.length > this.sendLimit)
      throw new Error('failed to write whole buffer');
    this.#out.push(...data);
  }
  plaintext(): Uint8Array {
    const plain = new Uint8Array(this.#plain);
    this.#plain = [];
    return plain;
  }
  close(): void {
    this.closed = true;
    this.#out.push(0xff);
  }
  /** Lets a test pretend the handshake produced bytes to send. */
  queueOutgoing(bytes: number[]): void {
    this.#out.push(...bytes);
  }
}

function socketOf(chunks: number[][]): { socket: ByteSocket; sent: number[] } {
  const sent: number[] = [];
  const socket: ByteSocket = {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
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

const collect = async (stream: ReadableStream<Uint8Array>) => {
  const out: number[] = [];
  for (const reader = stream.getReader(); ;) {
    const { value, done } = await reader.read();
    if (done) return out;
    if (value) out.push(...value);
  }
};

describe('tls pump', () => {
  it('feeds a chunk the session only half-takes until all of it is in', async () => {
    const session = new FakeSession(1);
    const { socket } = socketOf([[1], [10, 11, 12, 13, 14]]);

    const tunnel = await tlsTunnel(socket, session);
    expect(await collect(tunnel.readable)).toEqual([10, 11, 12, 13, 14]);
    // Two bytes at a time, so five bytes took three passes — none dropped.
    expect(session.taken).toEqual([1, 10, 11, 12, 13, 14]);
  });

  it('writes the handshake out before waiting to be answered', async () => {
    const session = new FakeSession(1);
    session.queueOutgoing([0xa0, 0xa1]);
    const { socket, sent } = socketOf([[1]]);

    await tlsTunnel(socket, session);
    expect(sent).toEqual([0xa0, 0xa1]);
  });

  it('fails when the peer hangs up mid-handshake', async () => {
    const session = new FakeSession(99);
    const { socket } = socketOf([[1]]);
    await expect(tlsTunnel(socket, session)).rejects.toThrow(TlsError);
  });

  it('encrypts what is written and sends a close notification', async () => {
    const session = new FakeSession(1);
    const { socket, sent } = socketOf([[1]]);

    const tunnel = await tlsTunnel(socket, session);
    const writer = tunnel.writable.getWriter();
    await writer.write(new Uint8Array([7, 8]));
    await writer.close();

    expect(sent).toEqual([7, 8, 0xff]);
    expect(session.closed).toBe(true);
  });

  it('drains plaintext between passes, so a big chunk does not fill the session', async () => {
    // Two bytes a pass and a limit of two: reading only at the end would fail.
    const session = new FakeSession(1, 2);
    const body = Array.from({ length: 40 }, (_, i) => i);
    const { socket } = socketOf([[1], body]);

    const tunnel = await tlsTunnel(socket, session);
    expect(await collect(tunnel.readable)).toEqual(body);
  });

  it('writes a body larger than the session buffers in pieces', async () => {
    const session = new FakeSession(1, Infinity, 20_000);
    const { socket, sent } = socketOf([[1]]);

    const tunnel = await tlsTunnel(socket, session);
    const writer = tunnel.writable.getWriter();
    await writer.write(new Uint8Array(100_000).fill(3));

    expect(sent.length).toBe(100_000);
  });
});
