/**
 * What a request looks like on an HTTP/2 connection: the profile it is
 * opened with, its header block, and the frames that carry it; and what a
 * connection is made of.
 */

import { arrange } from '../../fingerprint/order';
import type { Decoders } from '../decompress';
import { USER_AGENT } from '../user-agent';
import { encodeFrame, Flags, FrameType, Setting } from './frames';
import { once } from './flow';
import { Hpack } from './hpack';
import type { Header } from './hpack';

export interface Http2Socket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

export interface Http2ConnectionOptions {
  /** Hangs up underneath: the socket the frames ride on. */
  close?: (() => void) | undefined;
  /** Told whenever the last open stream finishes. */
  onIdle?: (() => void) | undefined;
}

export interface Http2Profile {
  /** Sent verbatim, in this order: a browser is known by its SETTINGS. */
  settings: readonly (readonly [number, number])[];
  /** The connection-level window increment sent straight after the preface. */
  windowUpdate: number;
  /** Pseudo-header order, as the letters an Akamai fingerprint uses. */
  pseudoHeaderOrder: readonly ('m' | 'a' | 's' | 'p')[];
  /**
   * The priority the request's HEADERS frame carries. Chrome and Firefox send
   * one, each with its own weight; Safari sends none, which is left out here.
   */
  priority?: { weight: number; exclusive: boolean } | undefined;
  /**
   * Make each stream depend, exclusively, on the newest stream still open at
   * its priority or above, and on none when there is no such stream — as
   * Chromium does, so requests at once form a chain where requests one after
   * another each start from the root. Left out, every stream depends on none.
   */
  dependOnOpen?: boolean | undefined;
  /** The first stream a request goes on. Firefox starts at 3. Default: 1. */
  firstStream?: number | undefined;
  /**
   * Sent for each new stream straight after its HEADERS, widening that
   * stream's window past the SETTINGS one, as Firefox does: 128 KB to 12 MB.
   */
  streamWindowUpdate?: number | undefined;
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

export interface Http2Options {
  /**
   * Send the body as it arrives instead of reading it into memory first. For
   * uploads too large to hold.
   */
  streamBody?: boolean | undefined;
  /** Decoders beyond gzip and deflate; see `Decoders`. */
  decoders?: Decoders | undefined;
  /** The order to write headers in, as `arrange` takes it; left out, as given. */
  headerOrder?: readonly string[] | undefined;
}

export interface Http2RequestOptions extends Http2Options {
  /**
   * Where this request's pseudo-header order and priority come from; a
   * fetch() weighs less than a page load. The connection's own opening
   * profile when left out.
   */
  profile?: Http2Profile | undefined;
  /** Resets this stream alone; the connection carries on. */
  signal?: AbortSignal | undefined;
}

const PSEUDO = { m: ':method', a: ':authority', s: ':scheme', p: ':path' } as const;

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

export function requestHeaders(
  request: Request,
  url: URL,
  profile: Http2Profile,
  length: number | null,
  order: readonly string[] | undefined,
): Header[] {
  const regular: Header[] = [];
  if (!request.headers.has('user-agent')) regular.push(['user-agent', USER_AGENT]);
  for (const [name, value] of request.headers) {
    const lower = name.toLowerCase();
    if (FORBIDDEN.includes(lower) || lower === 'host' || lower === 'content-length') continue;
    // TE is allowed, but only to say `trailers`.
    if (lower === 'te' && value.trim().toLowerCase() !== 'trailers') continue;
    regular.push([lower, value]);
  }
  // Browsers state the length of a body they hold, HTTP/2 or not.
  if (length !== null) regular.push(['content-length', String(length)]);
  const pseudo = pseudoHeaders(request, url, profile.pseudoHeaderOrder);
  return [...pseudo, ...(order ? arrange(regular, order) : regular)];
}

/**
 * Puts the priority fields in front of a header block: the exclusive bit and
 * the stream depended on, then the weight less one, as RFC 9113 §6.2 writes
 * it.
 */
export function withPriority(
  block: Uint8Array,
  priority: Http2Profile['priority'],
  dependsOn = 0,
): Uint8Array {
  if (priority === undefined) return block;
  const out = new Uint8Array(5 + block.length);
  new DataView(out.buffer).setUint32(0, (priority.exclusive ? 0x8000_0000 : 0) | dependsOn);
  out[4] = priority.weight - 1;
  out.set(block, 5);
  return out;
}

/**
 * The stream a new one depends on, as Chromium chooses it: the newest still
 * open at its priority or above — weight standing for priority, which is how
 * Chromium maps one to the other — or none.
 */
export function dependency(
  open: Iterable<{ id: number; weight: number }>,
  priority: Http2Profile['priority'],
): number {
  if (priority === undefined) return 0;
  let found = 0;
  for (const stream of open) if (stream.weight >= priority.weight) found = stream.id;
  return found;
}

export function joined(parts: readonly Uint8Array[]): Uint8Array {
  if (parts.length === 1) return parts[0]!;
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

/**
 * HEADERS, and CONTINUATION for whatever does not fit in `maxFrame`, joined
 * so they go out in one write and no other stream's frame lands between them.
 */
export function headerFrames(
  id: number,
  block: Uint8Array,
  { endStream, priority, maxFrame }: { endStream: boolean; priority: boolean; maxFrame: number },
): Uint8Array {
  const frames: Uint8Array[] = [];
  let at = 0;
  do {
    const piece = block.subarray(at, at + maxFrame);
    at += piece.length;
    const last = at >= block.length;
    const first = frames.length === 0;
    const flags =
      (last ? Flags.EndHeaders : 0) |
      (first && endStream ? Flags.EndStream : 0) |
      (first && priority ? Flags.Priority : 0);
    frames.push(encodeFrame(first ? FrameType.Headers : FrameType.Continuation, flags, id, piece));
  } while (at < block.length);
  return joined(frames);
}

/**
 * A request as it goes out on stream `id`: its HEADERS frames, and its body
 * when it has one. A body already in memory is sent whole, which also tells
 * us up front whether HEADERS ends the stream; a streamed one is read as it
 * goes.
 */
export async function outgoing(
  request: Request,
  id: number,
  profile: Http2Profile,
  options: {
    streamBody: boolean;
    headerOrder: readonly string[] | undefined;
    maxFrame: number;
    dependsOn: number;
  },
): Promise<{ frames: Uint8Array; body: ReadableStream<Uint8Array> | null }> {
  const { streamBody, headerOrder, maxFrame, dependsOn } = options;
  const buffered =
    streamBody || request.body === null ? null : new Uint8Array(await request.arrayBuffer());
  const body =
    request.body === null
      ? null
      : streamBody
        ? request.body
        : buffered!.byteLength === 0
          ? null
          : once(buffered!);
  const length = request.body === null || buffered === null ? null : buffered.byteLength;
  const headers = requestHeaders(request, new URL(request.url), profile, length, headerOrder);
  const block = withPriority(new Hpack().encode(headers), profile.priority, dependsOn);
  const frames = headerFrames(id, block, {
    endStream: body === null,
    priority: profile.priority !== undefined,
    maxFrame,
  });
  return { frames, body };
}
