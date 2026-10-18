/** A server's side of HTTP/2 for the tests: frames in, frames out, in memory. */

import { Hpack } from '../../src/http/h2/hpack';
import {
  encodeFrame,
  encodeSettings,
  Flags,
  FrameType,
  PREFACE,
  Setting,
} from '../../src/http/h2/frames';
import type { Http2Socket } from '../../src/http/h2/request';

/** Splits a stream of frames the way a peer would read them. */
export function framesIn(
  written: number[],
): { type: number; flags: number; stream: number; payload: Uint8Array }[] {
  const data = new Uint8Array(written);
  const view = new DataView(data.buffer);
  const out = [];
  let at = PREFACE.length; // the preface leads and is not a frame
  while (at + 9 <= data.length) {
    const length = (data[at]! << 16) | view.getUint16(at + 1);
    out.push({
      type: data[at + 3]!,
      flags: data[at + 4]!,
      stream: view.getUint32(at + 5) & 0x7fffffff,
      payload: data.subarray(at + 9, at + 9 + length),
    });
    at += 9 + length;
  }
  return out;
}

export const serverHeaders = (headers: readonly (readonly [string, string])[], flags: number) =>
  encodeFrame(FrameType.Headers, Flags.EndHeaders | flags, 1, new Hpack().encode(headers));

/**
 * A socket whose server answers once the request has ended — its HEADERS or
 * last DATA carrying END_STREAM — as a real one does. `early` goes out at
 * once instead: settings, window updates, or an answer that will not wait
 * for the body.
 */
export function socketOf(
  answer: Uint8Array[],
  early: Uint8Array[] = [],
): { socket: Http2Socket; written: number[] } {
  const written: number[] = [];
  let release: () => void = () => undefined;
  const ended = () =>
    framesIn(written).some(
      (f) =>
        f.stream !== 0 &&
        (f.type === FrameType.Headers || f.type === FrameType.Data) &&
        (f.flags & Flags.EndStream) !== 0,
    );
  return {
    socket: {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          for (const frame of early) controller.enqueue(frame);
          release = () => {
            release = () => undefined;
            for (const frame of answer) controller.enqueue(frame);
            controller.close();
          };
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
          if (ended()) release();
        },
      }),
    },
    written,
  };
}

export const SETTINGS = encodeFrame(
  FrameType.Settings,
  0,
  0,
  encodeSettings([[Setting.MaxFrameSize, 16384]]),
);
export const OK = serverHeaders(
  [
    [':status', '200'],
    ['content-type', 'application/json'],
  ],
  0,
);
export const data = (text: string, end = true) =>
  encodeFrame(FrameType.Data, end ? Flags.EndStream : 0, 1, new TextEncoder().encode(text));
