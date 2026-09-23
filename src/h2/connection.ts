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
  if (body !== null && body.byteLength > 0) {
    await writer.write(encodeFrame(FrameType.Data, Flags.EndStream, STREAM, body));
  }

  return await readResponse(reader, writer, hpack);
}

/** Reads frames until the response headers arrive, then hands back the body. */
async function readResponse(
  reader: ByteReader,
  writer: ByteWriter,
  hpack: Hpack,
): Promise<Response> {
  let maxFrame = DEFAULT_MAX_FRAME;
  let headerBlock = new Uint8Array(0);
  let expectingContinuation = false;

  for (;;) {
    const frame = await readFrame(reader, Math.max(maxFrame, DEFAULT_MAX_FRAME));

    if (expectingContinuation && frame.type !== FrameType.Continuation) {
      throw new Http2Error('the server interrupted a header block');
    }

    switch (frame.type) {
      case FrameType.Settings:
        if ((frame.flags & Flags.Ack) === 0) {
          const settings = decodeSettings(frame.payload);
          maxFrame = settings.get(Setting.MaxFrameSize) ?? maxFrame;
          await writer.write(encodeFrame(FrameType.Settings, Flags.Ack, 0, new Uint8Array(0)));
        }
        break;

      case FrameType.Ping:
        if ((frame.flags & Flags.Ack) === 0) {
          await writer.write(encodeFrame(FrameType.Ping, Flags.Ack, 0, frame.payload));
        }
        break;

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
        return buildResponse(status, headers, done ? null : streamBody(reader, writer, maxFrame));
      }

      default:
        // PRIORITY, WINDOW_UPDATE, PUSH_PROMISE and anything newer: a client
        // that only reads one stream has nothing to do with them.
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

/** DATA frames until END_STREAM, topping the flow-control window up as it goes. */
function streamBody(
  reader: ByteReader,
  writer: ByteWriter,
  maxFrame: number,
): ReadableStream<Uint8Array> {
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
        if (outstanding > 1 << 20) {
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
