/**
 * HTTP/2 flow control, and sending a request body within it.
 *
 * A server grants a window per stream and per connection, and a body sent
 * past either is a FLOW_CONTROL_ERROR. This keeps count of both, reads the
 * server's WINDOW_UPDATEs while it waits for room, and sends a body — held in
 * memory or still arriving — in frames that fit.
 */

import type { ByteReader, ByteWriter } from '../../net/bytes';
import {
  decodeSettings,
  encodeFrame,
  Flags,
  FrameType,
  readFrame,
  Setting,
  type Frame,
} from './frames';

export const STREAM = 1;
export const DEFAULT_MAX_FRAME = 16_384;
/** Every window starts here until a SETTINGS frame or WINDOW_UPDATE says more. */
export const DEFAULT_WINDOW = 65_535;

/**
 * What the server allows us to send: its frame size, and what is left of the
 * stream's and the connection's windows. A body sent past either window is a
 * FLOW_CONTROL_ERROR, which a strict server answers by resetting the stream.
 */
export interface Allowance {
  maxFrame: number;
  stream: number;
  connection: number;
}

/**
 * Applies a frame that only adjusts the connection — SETTINGS, WINDOW_UPDATE,
 * PING — answering it where the protocol says to. Returns false for anything
 * that belongs to the response instead.
 */
export async function control(
  frame: Frame,
  allowance: Allowance,
  writer: ByteWriter,
): Promise<boolean> {
  switch (frame.type) {
    case FrameType.Settings: {
      if ((frame.flags & Flags.Ack) !== 0) return true;
      const settings = decodeSettings(frame.payload);
      allowance.maxFrame = settings.get(Setting.MaxFrameSize) ?? allowance.maxFrame;
      const window = settings.get(Setting.InitialWindowSize);
      // A new initial size moves an open stream's window by the difference.
      if (window !== undefined) allowance.stream += window - DEFAULT_WINDOW;
      await writer.write(encodeFrame(FrameType.Settings, Flags.Ack, 0, new Uint8Array(0)));
      return true;
    }
    case FrameType.WindowUpdate: {
      if (frame.payload.length < 4) return true;
      const view = new DataView(frame.payload.buffer, frame.payload.byteOffset);
      const increment = view.getUint32(0) & 0x7fffffff;
      if (frame.stream === 0) allowance.connection += increment;
      else if (frame.stream === STREAM) allowance.stream += increment;
      return true;
    }
    case FrameType.Ping:
      if ((frame.flags & Flags.Ack) === 0) {
        await writer.write(encodeFrame(FrameType.Ping, Flags.Ack, 0, frame.payload));
      }
      return true;
    default:
      return false;
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
async function* withLast(
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

/**
 * Sends the body in frames the server has room for, reading its window
 * updates while it waits. Anything else that arrives meanwhile is kept for
 * the response; if that is the answer itself, or a reset, sending stops —
 * the server has decided without the rest of the body.
 */
export async function upload(
  body: ReadableStream<Uint8Array>,
  reader: ByteReader,
  writer: ByteWriter,
  allowance: Allowance,
  held: Frame[],
): Promise<void> {
  let sent = false;
  for await (const [chunk, last] of withLast(body.getReader())) {
    for (let offset = 0; offset < chunk.length;) {
      const room = Math.min(allowance.maxFrame, allowance.stream, allowance.connection);
      if (room > 0) {
        const piece = chunk.subarray(offset, offset + room);
        offset += piece.length;
        const flags = last && offset === chunk.length ? Flags.EndStream : 0;
        await writer.write(encodeFrame(FrameType.Data, flags, STREAM, piece));
        allowance.stream -= piece.length;
        allowance.connection -= piece.length;
        sent = true;
        continue;
      }
      const frame = await readFrame(reader, Math.max(allowance.maxFrame, DEFAULT_MAX_FRAME));
      if (await control(frame, allowance, writer)) continue;
      held.push(frame);
      const final = [FrameType.Headers, FrameType.RstStream, FrameType.GoAway] as number[];
      if (final.includes(frame.type)) return;
    }
  }
  // A stream that turned out empty still has to be ended.
  if (!sent)
    await writer.write(encodeFrame(FrameType.Data, Flags.EndStream, STREAM, new Uint8Array(0)));
}
