/**
 * permessage-deflate (RFC 7692), the reading half.
 *
 * Chrome offers it on every WebSocket, so a handshake without it is one more
 * thing that is not Chrome. Only reading is needed: compression is chosen per
 * message by the sender, so ours go out plain and nothing is lost.
 *
 * Reading needs an inflater that keeps its window from one message to the
 * next and gives up everything it has at the end of each, which
 * `DecompressionStream` cannot do. A Node-style `zlib` can — Workers carry one
 * on a recent compatibility date — so this is offered only where one exists.
 */

import { WebSocketError } from './websocket-error';

/** What Chrome sends, word for word. */
export const DEFLATE_OFFER = 'permessage-deflate; client_max_window_bits';

/** Inflates one message at a time, carrying the window between them. */
export interface MessageInflater {
  /** One message's payload, as compressed, to its plain bytes. */
  inflate(data: Uint8Array, limit: number): Promise<Uint8Array>;
  close(): void;
}

export type InflaterFactory = () => MessageInflater;

/** What the server agreed to. */
export interface DeflateTerms {
  /** The server starts every message afresh, so its window may not be kept. */
  serverNoContextTakeover: boolean;
}

/**
 * Reads the server's `Sec-WebSocket-Extensions`. Anything but one
 * permessage-deflate with parameters RFC 7692 defines is refused: a frame we
 * cannot read is worse than no connection.
 */
export function acceptedDeflate(value: string): DeflateTerms {
  const extensions = value.split(',').map((e) => e.trim());
  const [name, ...params] = (extensions[0] ?? '').split(';').map((p) => p.trim());
  if (extensions.length !== 1 || name?.toLowerCase() !== 'permessage-deflate') {
    throw new WebSocketError(`the server turned on an extension never offered: ${value}`);
  }
  const terms: DeflateTerms = { serverNoContextTakeover: false };
  const seen = new Set<string>();
  for (const param of params) {
    const [key = '', raw] = param.split('=').map((p) => p.trim());
    const lower = key.toLowerCase();
    if (seen.has(lower)) throw new WebSocketError(`permessage-deflate repeats ${key}`);
    seen.add(lower);
    const bits = raw === undefined ? undefined : Number(raw.replace(/^"|"$/g, ''));
    if (lower === 'server_no_context_takeover' && raw === undefined) {
      terms.serverNoContextTakeover = true;
    } else if (lower === 'client_no_context_takeover' && raw === undefined) {
      // Ours go out uncompressed, so there is no context of ours to reset.
    } else if (
      (lower === 'server_max_window_bits' || lower === 'client_max_window_bits') &&
      bits !== undefined &&
      Number.isInteger(bits) &&
      bits >= 8 &&
      bits <= 15
    ) {
      // An inflater with the largest window reads a smaller one too.
    } else {
      throw new WebSocketError(`permessage-deflate parameter not understood: ${param}`);
    }
  }
  return terms;
}

/** RFC 7692 §7.2.2: the sender strips this; the reader puts it back. */
const TAIL = new Uint8Array([0x00, 0x00, 0xff, 0xff]);

/** The part of a Node-style inflate stream this needs. */
interface InflateStream {
  write(chunk: Uint8Array): boolean;
  flush(kind: number, done: () => void): void;
  on(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  once(event: 'error', listener: (error: Error) => void): unknown;
  off(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  off(event: 'error', listener: (error: Error) => void): unknown;
  close(): void;
}

/** The part of a Node-style `zlib` module this uses. */
export interface InflateModule {
  createInflateRaw?: (() => InflateStream) | undefined;
  constants?: { Z_SYNC_FLUSH?: number | undefined } | undefined;
}

/** Inflaters over a Node-style `zlib`, or nothing where it has no raw inflate. */
export function zlibInflater(zlib: InflateModule | undefined): InflaterFactory | undefined {
  const create = zlib?.createInflateRaw?.bind(zlib);
  const syncFlush = zlib?.constants?.Z_SYNC_FLUSH ?? 2;
  if (create === undefined) return undefined;
  return () => {
    const stream = create();
    return {
      inflate(data, limit) {
        return new Promise((resolve, reject) => {
          const parts: Uint8Array[] = [];
          let size = 0;
          const onData = (chunk: Uint8Array) => {
            size += chunk.length;
            // Past the limit nothing more is kept; the caller hears of it below.
            if (size <= limit) parts.push(new Uint8Array(chunk));
          };
          const onError = (error: Error) => {
            stream.off('data', onData);
            reject(error);
          };
          stream.on('data', onData);
          stream.once('error', onError);
          const input = new Uint8Array(data.length + TAIL.length);
          input.set(data);
          input.set(TAIL, data.length);
          stream.write(input);
          stream.flush(syncFlush, () => {
            stream.off('data', onData);
            stream.off('error', onError);
            if (size > limit) {
              reject(new RangeError(`a message inflating past ${limit} bytes`));
              return;
            }
            const out = new Uint8Array(size);
            let at = 0;
            for (const part of parts) {
              out.set(part, at);
              at += part.length;
            }
            resolve(out);
          });
        });
      },
      close: () => stream.close(),
    };
  };
}
