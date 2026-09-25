/**
 * Driving a TLS state machine over a raw tunnel.
 *
 * The session does no I/O: it takes ciphertext in, gives ciphertext out, and
 * exchanges plaintext with us. Everything that touches the socket is here, in
 * plain TypeScript, so the pump can be tested without building any WebAssembly.
 */

import type { ByteSocket } from '../net/socket';

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
  /**
   * The certificates the server sent, as `(length u32, DER)` records, once
   * they have been checked. Optional: only needed to complete a short chain.
   */
  presentedChain?(): Uint8Array;
  /** What ALPN settled on, once the handshake is done. */
  readonly protocol?: string | undefined;
  /** Whether the handshake resumed an earlier session. Optional. */
  resumed?(): boolean;
  close(): void;
}

/** What a second attempt at a connection asks of the TLS client. */
export interface TlsOptions {
  /** Certificates fetched to complete a chain the server sent short; see `aia.ts`. */
  intermediates?: readonly Uint8Array[] | undefined;
  /** Offer only the signature schemes the verifier can check. */
  verifiableSignatures?: boolean | undefined;
}

/** Builds a TLS client for one connection. */
export type TlsFactory = (hostname: string, alpn?: string, options?: TlsOptions) => TlsSession;

export class TlsError extends Error {
  override name = 'TlsError';
}

/**
 * The most plaintext handed to the session at once. rustls buffers what it
 * has not yet encrypted and refuses a write past its limit (64 KB), so a
 * large body has to go through in pieces, each flushed before the next.
 */
const SEND_SLICE = 16_384;

/**
 * Feeds a whole chunk in, however many passes the session needs to take it,
 * and returns the plaintext that came out. It is drained after every pass:
 * rustls holds at most 16 KB of unread plaintext and refuses to read further,
 * so feeding a large chunk first and reading afterwards fails on any body
 * bigger than that.
 */
function receiveAll(session: TlsSession, chunk: Uint8Array): Uint8Array[] {
  const plain: Uint8Array[] = [];
  for (let offset = 0; offset < chunk.length;) {
    const taken = session.receive(chunk.subarray(offset));
    if (taken <= 0) throw new TlsError('the TLS session stopped accepting data');
    offset += taken;
    const out = session.plaintext();
    if (out.length > 0) plain.push(out);
  }
  return plain;
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
): Promise<{
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  /** What ALPN settled on: `h2`, `http/1.1`, or nothing if it went unasked. */
  protocol: string | undefined;
}> {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();

  const flush = async () => {
    const out = session.outgoing();
    if (out.length > 0) await writer.write(out);
  };

  // Anything the server volunteered along with the handshake is already
  // decrypted and would be lost if the reader started from the socket again.
  const early: Uint8Array[] = [];
  while (session.handshaking) {
    await flush();
    if (!session.handshaking) break;
    const { value, done } = await reader.read();
    if (done) throw new TlsError('the connection closed during the TLS handshake');
    if (value) early.push(...receiveAll(session, value));
  }
  await flush();
  const left = session.plaintext();
  if (left.length > 0) early.push(left);

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const plain of early) controller.enqueue(plain);
    },
    async pull(controller) {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        const plain = value ? receiveAll(session, value) : [];
        // A record may span several TCP reads and yield nothing yet; keep
        // reading rather than closing the body on an empty pass.
        if (plain.length > 0) {
          for (const out of plain) controller.enqueue(out);
          return;
        }
      }
    },
    cancel: (reason) => reader.cancel(reason),
  });

  const writable = new WritableStream<Uint8Array>({
    async write(chunk) {
      for (let offset = 0; offset < chunk.length; offset += SEND_SLICE) {
        session.send(chunk.subarray(offset, offset + SEND_SLICE));
        await flush();
      }
    },
    async close() {
      session.close();
      await flush();
    },
  });

  return { readable, writable, protocol: session.protocol };
}
