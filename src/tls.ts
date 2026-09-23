/**
 * Driving a TLS state machine over a raw tunnel.
 *
 * The session does no I/O: it takes ciphertext in, gives ciphertext out, and
 * exchanges plaintext with us. Everything that touches the socket is here, in
 * plain TypeScript, so the pump can be tested without building any WebAssembly.
 */

import type { ByteSocket } from './socket';

/** A TLS client for one connection. `rust-tls/` implements this in WebAssembly. */
export interface TlsSession {
  /**
   * Hands over bytes from the network and answers how many it took. It does not
   * always take the whole slice, so a caller must loop from the returned
   * offset — feeding a large record once and moving on silently loses data.
   */
  receive(data: Uint8Array): number;
  /** Ciphertext waiting to go out. */
  outgoing(): Uint8Array;
  /** Queues plaintext to be encrypted. */
  send(data: Uint8Array): void;
  /** Plaintext decrypted so far. */
  plaintext(): Uint8Array;
  readonly handshaking: boolean;
  close(): void;
}

export type TlsFactory = (hostname: string, alpn?: string) => TlsSession;

export class TlsError extends Error {
  override name = 'TlsError';
}

/** Feeds a whole chunk in, however many passes the session needs to take it. */
function receiveAll(session: TlsSession, chunk: Uint8Array): void {
  for (let offset = 0; offset < chunk.length; ) {
    const taken = session.receive(chunk.subarray(offset));
    if (taken <= 0) throw new TlsError('the TLS session stopped accepting data');
    offset += taken;
  }
}

/**
 * Wraps `socket` in TLS for `hostname` and returns streams carrying plaintext.
 *
 * The handshake runs first so a bad certificate fails here rather than halfway
 * through someone's request.
 */
export async function tlsTunnel(
  socket: ByteSocket,
  session: TlsSession,
): Promise<{ readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> }> {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  const flush = async () => {
    const out = session.outgoing();
    if (out.length > 0) await writer.write(out);
  };

  while (session.handshaking) {
    await flush();
    if (!session.handshaking) break;
    const { value, done } = await reader.read();
    if (done) throw new TlsError('the connection closed during the TLS handshake');
    if (value) receiveAll(session, value);
  }
  await flush();

  // Anything the server volunteered along with the handshake is already
  // decrypted and would be lost if the reader started from the socket again.
  const early = session.plaintext();

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      if (early.length > 0) controller.enqueue(early);
    },
    async pull(controller) {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        if (value) receiveAll(session, value);
        const plain = session.plaintext();
        // A record may span several TCP reads and yield nothing yet; keep
        // reading rather than closing the body on an empty pass.
        if (plain.length > 0) {
          controller.enqueue(plain);
          return;
        }
      }
    },
    cancel: (reason) => reader.cancel(reason),
  });

  const writable = new WritableStream<Uint8Array>({
    async write(chunk) {
      session.send(chunk);
      await flush();
    },
    async close() {
      session.close();
      await flush();
    },
  });

  return { readable, writable };
}
