/**
 * HTTP/2 frames (RFC 9113 §4): a nine-byte header and a payload.
 *
 * Only what a client sending one request needs is here. Frames it can receive
 * but has nothing to do with — PRIORITY, PUSH_PROMISE — are read and dropped
 * rather than rejected, because a peer is allowed to send them.
 */

import type { ByteReader } from '../bytes';

export const FRAME_HEADER = 9;

export const FrameType = {
  Data: 0x0,
  Headers: 0x1,
  RstStream: 0x3,
  Settings: 0x4,
  Ping: 0x6,
  GoAway: 0x7,
  WindowUpdate: 0x8,
  Continuation: 0x9,
} as const;

export const Flags = {
  EndStream: 0x1,
  Ack: 0x1,
  EndHeaders: 0x4,
  Padded: 0x8,
  Priority: 0x20,
} as const;

/** The settings a client has an opinion about, by their wire identifiers. */
export const Setting = {
  HeaderTableSize: 0x1,
  EnablePush: 0x2,
  MaxConcurrentStreams: 0x3,
  InitialWindowSize: 0x4,
  MaxFrameSize: 0x5,
  MaxHeaderListSize: 0x6,
} as const;

export class Http2Error extends Error {
  override name = 'Http2Error';
}

export interface Frame {
  type: number;
  flags: number;
  stream: number;
  payload: Uint8Array;
}

/** `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, which every connection opens with. */
export const PREFACE = new Uint8Array([
  0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
  0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
]);

export function encodeFrame(type: number, flags: number, stream: number, payload: Uint8Array) {
  const frame = new Uint8Array(FRAME_HEADER + payload.length);
  const view = new DataView(frame.buffer);
  // A 24-bit length, which is why it is written as a byte and then a short.
  frame[0] = (payload.length >>> 16) & 0xff;
  view.setUint16(1, payload.length & 0xffff);
  frame[3] = type;
  frame[4] = flags;
  view.setUint32(5, stream & 0x7fffffff);
  frame.set(payload, FRAME_HEADER);
  return frame;
}

export async function readFrame(reader: ByteReader, maxFrame: number): Promise<Frame> {
  const header = await reader.exactly(FRAME_HEADER);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const length = (header[0]! << 16) | view.getUint16(1);
  if (length > maxFrame) {
    throw new Http2Error(`the server sent a ${length} byte frame, over the ${maxFrame} agreed`);
  }
  return {
    type: header[3]!,
    flags: header[4]!,
    stream: view.getUint32(5) & 0x7fffffff,
    payload: length === 0 ? new Uint8Array(0) : await reader.exactly(length),
  };
}

/** A SETTINGS payload: pairs of a 16-bit identifier and a 32-bit value. */
export function encodeSettings(settings: readonly (readonly [number, number])[]): Uint8Array {
  const payload = new Uint8Array(settings.length * 6);
  const view = new DataView(payload.buffer);
  settings.forEach(([id, value], i) => {
    view.setUint16(i * 6, id);
    view.setUint32(i * 6 + 2, value);
  });
  return payload;
}

export function decodeSettings(payload: Uint8Array): Map<number, number> {
  if (payload.length % 6 !== 0) throw new Http2Error('a SETTINGS frame was not a whole number');
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const settings = new Map<number, number>();
  for (let at = 0; at < payload.length; at += 6) {
    settings.set(view.getUint16(at), view.getUint32(at + 2));
  }
  return settings;
}

export function encodeWindowUpdate(increment: number): Uint8Array {
  const payload = new Uint8Array(4);
  new DataView(payload.buffer).setUint32(0, increment & 0x7fffffff);
  return payload;
}

/** Strips the padding a DATA or HEADERS frame may carry. */
export function unpad(payload: Uint8Array, flags: number, priority: boolean): Uint8Array {
  let body = payload;
  let padding = 0;
  if ((flags & Flags.Padded) !== 0) {
    padding = body[0]!;
    body = body.subarray(1);
  }
  if (priority && (flags & Flags.Priority) !== 0) body = body.subarray(5);
  if (padding > body.length) throw new Http2Error('a frame claimed more padding than it had');
  return padding === 0 ? body : body.subarray(0, body.length - padding);
}

/** RFC 9113 §7: the error codes, by the names a reader would want to see. */
const ERRORS = [
  'no error',
  'protocol error',
  'internal error',
  'flow control error',
  'settings timeout',
  'stream closed',
  'frame size error',
  'refused stream',
  'cancel',
  'compression error',
  'connect error',
  'enhance your calm',
  'inadequate security',
  'HTTP/1.1 required',
];

export const errorName = (code: number) => ERRORS[code] ?? `error ${code}`;
