/**
 * One HTTP/2 request over a socket we opened ourselves.
 *
 * The scope is a single stream on a fresh connection, which is what a proxied
 * request needs and skips most of HTTP/2's complexity: no multiplexing, no
 * server push, no priority tree. What is left is the preface, a SETTINGS
 * exchange, one HEADERS frame out, and DATA frames in until the stream ends.
 *
 * The settings we send are part of the fingerprint — a browser is as
 * recognisable by its SETTINGS frame as by its ClientHello — so they come from
 * the caller rather than from here.
 */

import { ByteReader, ByteWriter } from '../bytes';
import { decompressed } from '../decompress';
import { Hpack, type Header } from './hpack';
import {
  decodeSettings,
  encodeFrame,
  encodeSettings,
  encodeWindowUpdate,
  errorName,
  Flags,
  FrameType,
  Http2Error,
  PREFACE,
  type Frame,
  readFrame,
  Setting,
  unpad,
} from './frames';

export interface Http2Socket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

export interface Http2Profile {
  /** Sent verbatim, in this order: a browser is known by its SETTINGS. */
  settings: readonly (readonly [number, number])[];
  /** The connection-level window increment sent straight after the preface. */
  windowUpdate: number;
  /** Pseudo-header order, as the letters an Akamai fingerprint uses. */
  pseudoHeaderOrder: readonly ('m' | 'a' | 's' | 'p')[];
}

/** What Chrome sends, and a reasonable default for anything else. */
export const DEFAULT_PROFILE: Http2Profile = {
  settings: [
    [Setting.HeaderTableSize, 65536],
    [Setting.EnablePush, 0],
    [Setting.InitialWindowSize, 6291456],
    [Setting.MaxHeaderListSize, 262144],
  ],
  windowUpdate: 15663105,
  pseudoHeaderOrder: ['m', 'a', 's', 'p'],
};

const PSEUDO = { m: ':method', a: ':authority', s: ':scheme', p: ':path' } as const;

const STREAM = 1;
const DEFAULT_MAX_FRAME = 16_384;
/** Every window starts here until a SETTINGS frame or WINDOW_UPDATE says more. */
const DEFAULT_WINDOW = 65_535;

/**
 * What the server allows us to send: its frame size, and what is left of the
 * stream's and the connection's windows. A body sent past either window is a
 * FLOW_CONTROL_ERROR, which a strict server answers by resetting the stream.
 */
interface Allowance {
  maxFrame: number;
  stream: number;
  connection: number;
}

/**
 * Applies a frame that only adjusts the connection — SETTINGS, WINDOW_UPDATE,
 * PING — answering it where the protocol says to. Returns false for anything
 * that belongs to the response instead.
 */
async function control(frame: Frame, allowance: Allowance, writer: ByteWriter): Promise<boolean> {
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

/**
 * Sends the body in frames the server has room for, reading its window
 * updates while it waits. Anything else that arrives meanwhile is kept for
 * the response; if that is the answer itself, or a reset, sending stops —
 * the server has decided without the rest of the body.
 */
async function upload(
  body: Uint8Array,
  reader: ByteReader,
  writer: ByteWriter,
  allowance: Allowance,
  held: Frame[],
): Promise<void> {
  for (let offset = 0; offset < body.length;) {
    const room = Math.min(allowance.maxFrame, allowance.stream, allowance.connection);
    if (room > 0) {
      const piece = body.subarray(offset, offset + room);
      offset += piece.length;
      const flags = offset === body.length ? Flags.EndStream : 0;
      await writer.write(encodeFrame(FrameType.Data, flags, STREAM, piece));
      allowance.stream -= piece.length;
      allowance.connection -= piece.length;
      continue;
    }
    const frame = await readFrame(reader, Math.max(allowance.maxFrame, DEFAULT_MAX_FRAME));
    if (await control(frame, allowance, writer)) continue;
    held.push(frame);
    const final = [FrameType.Headers, FrameType.RstStream, FrameType.GoAway] as number[];
    if (final.includes(frame.type)) return;
  }
}

function pseudoHeaders(request: Request, url: URL, order: Http2Profile['pseudoHeaderOrder']) {
  const values = {
    m: request.method,
    a: url.host,
    s: url.protocol.slice(0, -1),
    p: `${url.pathname}${url.search}`,
  };
  return order.map((key): Header => [PSEUDO[key], values[key]]);
}

/** Headers that mean nothing in HTTP/2, which forbids them outright. */
const FORBIDDEN = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade'];

function requestHeaders(request: Request, url: URL, profile: Http2Profile): Header[] {
  const headers = pseudoHeaders(request, url, profile.pseudoHeaderOrder);
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (FORBIDDEN.includes(lower) || lower === 'host') continue;
    // TE is allowed, but only to say `trailers`.
    if (lower === 'te' && value.trim().toLowerCase() !== 'trailers') continue;
    headers.push([lower, value]);
  }
  return headers;
}

/**
 * Sends `request` and returns the answer with its body still streaming.
 * `socket` is spent afterwards; closing it is the caller's job.
 */
export async function http2Fetch(
  socket: Http2Socket,
  request: Request,
  profile: Http2Profile = DEFAULT_PROFILE,
): Promise<Response> {
  const url = new URL(request.url);
  const body = request.body === null ? null : new Uint8Array(await request.arrayBuffer());

  const writer = new ByteWriter(socket.writable);
  const reader = new ByteReader(socket.readable);
  const hpack = new Hpack();

  await writer.write(PREFACE);
  await writer.write(encodeFrame(FrameType.Settings, 0, 0, encodeSettings(profile.settings)));
  if (profile.windowUpdate > 0) {
    await writer.write(
      encodeFrame(FrameType.WindowUpdate, 0, 0, encodeWindowUpdate(profile.windowUpdate)),
    );
  }

  const block = hpack.encode(requestHeaders(request, url, profile));
  const endStream = body === null || body.byteLength === 0 ? Flags.EndStream : 0;
  await writer.write(encodeFrame(FrameType.Headers, Flags.EndHeaders | endStream, STREAM, block));
  const allowance: Allowance = {
    maxFrame: DEFAULT_MAX_FRAME,
    stream: DEFAULT_WINDOW,
    connection: DEFAULT_WINDOW,
  };
  const held: Frame[] = [];
  if (body !== null && body.byteLength > 0) {
    await upload(body, reader, writer, allowance, held);
  }

  return await readResponse(reader, writer, hpack, allowance, held, receiveWindows(profile));
}

/**
 * The windows we granted the server: the stream's from our SETTINGS, the
 * connection's from the default plus the update sent after the preface.
 */
function receiveWindows(profile: Http2Profile) {
  const initial = profile.settings.find(([id]) => id === Setting.InitialWindowSize)?.[1];
  return {
    stream: initial ?? DEFAULT_WINDOW,
    connection: DEFAULT_WINDOW + profile.windowUpdate,
  };
}

/** Reads frames until the response headers arrive, then hands back the body. */
async function readResponse(
  reader: ByteReader,
  writer: ByteWriter,
  hpack: Hpack,
  allowance: Allowance,
  held: Frame[],
  windows: { stream: number; connection: number },
): Promise<Response> {
  let headerBlock = new Uint8Array(0);
  let expectingContinuation = false;

  for (;;) {
    const frame =
      held.shift() ?? (await readFrame(reader, Math.max(allowance.maxFrame, DEFAULT_MAX_FRAME)));

    if (expectingContinuation && frame.type !== FrameType.Continuation) {
      throw new Http2Error('the server interrupted a header block');
    }
    if (await control(frame, allowance, writer)) continue;

    switch (frame.type) {
      case FrameType.GoAway: {
        const view = new DataView(frame.payload.buffer, frame.payload.byteOffset);
        const code = frame.payload.length >= 8 ? view.getUint32(4) : 0;
        throw new Http2Error(`the server closed the connection: ${errorName(code)}`);
      }

      case FrameType.RstStream: {
        const view = new DataView(frame.payload.buffer, frame.payload.byteOffset);
        const code = frame.payload.length >= 4 ? view.getUint32(0) : 0;
        throw new Http2Error(`the server reset the stream: ${errorName(code)}`);
      }

      case FrameType.Headers:
      case FrameType.Continuation: {
        const piece =
          frame.type === FrameType.Headers
            ? unpad(frame.payload, frame.flags, true)
            : frame.payload;
        const joined = new Uint8Array(headerBlock.length + piece.length);
        joined.set(headerBlock);
        joined.set(piece, headerBlock.length);
        headerBlock = joined;
        expectingContinuation = (frame.flags & Flags.EndHeaders) === 0;
        if (expectingContinuation) break;

        const headers = hpack.decode(headerBlock);
        const status = Number(headers.find(([name]) => name === ':status')?.[1] ?? 0);
        if (!Number.isInteger(status) || status < 100) {
          throw new Http2Error('the server sent no usable :status');
        }
        // A 1xx is informational: the real headers are still to come.
        if (status < 200) {
          headerBlock = new Uint8Array(0);
          break;
        }
        const done = (frame.flags & Flags.EndStream) !== 0;
        return buildResponse(
          status,
          headers,
          done ? null : streamBody(reader, writer, allowance.maxFrame, windows),
        );
      }

      default:
        // PRIORITY, PUSH_PROMISE and anything newer: a client that only
        // reads one stream has nothing to do with them.
        break;
    }
  }
}

function buildResponse(
  status: number,
  headers: readonly Header[],
  body: ReadableStream<Uint8Array> | null,
): Response {
  const out = new Headers();
  for (const [name, value] of headers) {
    if (name.startsWith(':')) continue;
    out.append(name, value);
  }
  // As on HTTP/1.1: the caller asked for a response, not for gzip.
  const plain = body === null ? null : decompressed(body, out);
  return new Response(plain, { status, headers: out });
}

/**
 * DATA frames until END_STREAM, topping the flow-control window up as it goes.
 * The top-up comes at half of the smaller window we granted, as browsers do:
 * waiting any longer stalls a server that honours a small window — Firefox
 * grants a stream only 128 KB.
 */
function streamBody(
  reader: ByteReader,
  writer: ByteWriter,
  maxFrame: number,
  windows: { stream: number; connection: number },
): ReadableStream<Uint8Array> {
  const threshold = Math.min(windows.stream, windows.connection) / 2;
  let outstanding = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      for (;;) {
        const frame = await readFrame(reader, Math.max(maxFrame, DEFAULT_MAX_FRAME));
        if (frame.type === FrameType.GoAway || frame.type === FrameType.RstStream) {
          // The body is over either way; an error here would lose what arrived.
          controller.close();
          return;
        }
        if (frame.type !== FrameType.Data) continue;

        const data = unpad(frame.payload, frame.flags, false);
        // The window is spent on the padded length, not what survives it.
        outstanding += frame.payload.length;
        if (outstanding >= threshold) {
          const update = encodeWindowUpdate(outstanding);
          await writer.write(encodeFrame(FrameType.WindowUpdate, 0, 0, update));
          await writer.write(encodeFrame(FrameType.WindowUpdate, 0, STREAM, update));
          outstanding = 0;
        }
        if (data.length > 0) controller.enqueue(data);
        if ((frame.flags & Flags.EndStream) !== 0) {
          controller.close();
          return;
        }
        if (data.length > 0) return;
      }
    },
  });
}
