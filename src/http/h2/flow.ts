/**
 * HTTP/2 flow control: its constants, the windows we grant a server, and a
 * request body cut into chunks that know which one is last.
 */

import { encodeFrame, encodeWindowUpdate, FrameType } from './frames';

export const DEFAULT_MAX_FRAME = 16_384;
/** Every window starts here until a SETTINGS frame or WINDOW_UPDATE says more. */
export const DEFAULT_WINDOW = 65_535;

/** A stream's share of what we granted: its id and what it has read. */
export interface Receiving {
  readonly id: number;
  /** The server has ended it, so its window no longer matters. */
  readonly ended: boolean;
  /** Bytes read and not yet given back. */
  unacked: number;
}

/**
 * The windows we granted the server, given back as bytes are read: at half
 * of each, as browsers do. Waiting any longer stalls a server that honours a
 * small window — Firefox grants a stream only 128 KB.
 */
export class ReceiveWindows {
  #unacked = 0;

  constructor(
    readonly stream: number,
    readonly connection: number,
    readonly post: (frame: Uint8Array) => void,
  ) {}

  /** `cost` bytes were read: of `stream`, or of one already let go of. */
  consumed(stream: Receiving | undefined, cost: number): void {
    this.#unacked += cost;
    if (this.#unacked >= this.connection / 2) {
      this.post(encodeFrame(FrameType.WindowUpdate, 0, 0, encodeWindowUpdate(this.#unacked)));
      this.#unacked = 0;
    }
    if (stream === undefined || stream.ended) return;
    stream.unacked += cost;
    if (stream.unacked >= this.stream / 2) {
      this.post(
        encodeFrame(FrameType.WindowUpdate, 0, stream.id, encodeWindowUpdate(stream.unacked)),
      );
      stream.unacked = 0;
    }
  }
}

/** A stream of exactly one chunk, for a body already in memory. */
export const once = (bytes: Uint8Array) =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

/**
 * The body's chunks, each paired with whether it is the last: one chunk is
 * read ahead so the final DATA frame can carry END_STREAM, as a browser's
 * does, even when the body is a stream of unknown length. Empty chunks are
 * skipped. Stopping early cancels the source.
 */
export async function* withLast(
  source: ReadableStreamDefaultReader<Uint8Array>,
): AsyncGenerator<[Uint8Array, boolean]> {
  let finished = false;
  try {
    let previous: Uint8Array | undefined;
    for (;;) {
      const { value, done } = await source.read();
      if (done) break;
      if (value.byteLength === 0) continue;
      if (previous !== undefined) yield [previous, false];
      previous = value;
    }
    finished = true;
    if (previous !== undefined) yield [previous, true];
  } finally {
    if (!finished) await source.cancel().catch(() => undefined);
  }
}
