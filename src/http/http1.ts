/**
 * A small HTTP/1.1 client for a socket we opened ourselves.
 *
 * `fetch()` cannot ride an existing socket, so a tunnelled request has to be
 * written by hand. The scope is deliberately narrow: one request per
 * connection, `Connection: close`, and a response body that streams — an
 * answer token by token is the whole point of routing chat through here.
 */

import { ByteReader, ByteWriter } from '../net/bytes';
import { decompressed, defaultAcceptEncoding, type Decoders } from './decompress';
import { USER_AGENT } from './user-agent';
import { arrange } from '../fingerprint/order';

const CRLF = '\r\n';
const BODY_CHUNK = 16_384;

/** Hop-by-hop headers belong to one connection and must not be forwarded. */
const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
] as const;

const hopByHop = (name: string) => HOP_BY_HOP.includes(name.toLowerCase() as never);

export class Http1Error extends Error {
  override name = 'Http1Error';
}

export interface Http1Socket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

/** A status that carries no body, whatever the headers claim. */
const bodiless = (status: number) => status === 204 || status === 304 || status < 200;

/** How the request body is framed: a known length, chunks, or no body. */
type Framing = number | 'chunked' | null;

function requestHead(
  url: URL,
  method: string,
  headers: Headers,
  framing: Framing,
  decoders: Decoders,
  order: readonly string[] | undefined,
): string {
  const path = `${url.pathname}${url.search}`;
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${url.host}`];
  if (!headers.has('user-agent')) lines.push(`User-Agent: ${USER_AGENT}`);
  for (const [name, value] of order ? arrange(headers, order) : headers) {
    if (hopByHop(name)) continue;
    if (name.toLowerCase() === 'host' || name.toLowerCase() === 'content-length') continue;
    lines.push(`${name}: ${value}`);
  }
  if (framing === 'chunked') lines.push('Transfer-Encoding: chunked');
  else if (framing !== null) lines.push(`Content-Length: ${framing}`);
  // No pooling yet, so the server is told to hang up after answering.
  lines.push('Connection: close');
  // Only what can be undone is asked for: brotli and zstd only where the
  // runtime has a decoder for them.
  if (!headers.has('accept-encoding')) {
    lines.push(`Accept-Encoding: ${defaultAcceptEncoding(decoders)}`);
  }
  return `${lines.join(CRLF)}${CRLF}${CRLF}`;
}

function statusLine(line: string): { status: number; statusText: string } {
  const match = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(line);
  if (!match) throw new Http1Error(`the server did not answer with HTTP/1.1: ${line.slice(0, 80)}`);
  return { status: Number(match[1]), statusText: match[2] ?? '' };
}

async function readHeaders(reader: ByteReader): Promise<Headers> {
  const headers = new Headers();
  for (let seen = 0; ; seen++) {
    const line = await reader.line();
    if (line === '') return headers;
    if (seen >= 200) throw new Http1Error('the server sent too many headers');
    const colon = line.indexOf(':');
    if (colon <= 0) throw new Http1Error(`malformed header line: ${line.slice(0, 80)}`);
    // A header we cannot represent is dropped rather than failing the request.
    try {
      headers.append(line.slice(0, colon).trim(), line.slice(colon + 1).trim());
    } catch {
      continue;
    }
  }
}

/** A response's status line and headers, leaving the reader at its body. */
export async function readResponseHead(
  reader: ByteReader,
): Promise<{ status: number; statusText: string; headers: Headers }> {
  const { status, statusText } = statusLine(await reader.line());
  return { status, statusText, headers: await readHeaders(reader) };
}

/** RFC 9112 §7.1: size in hex, the bytes, CRLF, and a zero chunk to finish. */
function chunkedBody(reader: ByteReader): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const header = await reader.line();
      const size = Number.parseInt(header.split(';')[0] ?? '', 16);
      if (!Number.isInteger(size) || size < 0) {
        throw new Http1Error(`malformed chunk size: ${header.slice(0, 40)}`);
      }
      if (size === 0) {
        while ((await reader.line()) !== '') continue; // trailers
        controller.close();
        return;
      }
      controller.enqueue(await reader.exactly(size));
      await reader.exactly(2); // the CRLF closing the chunk
    },
  });
}

function countedBody(reader: ByteReader, length: number): ReadableStream<Uint8Array> {
  let left = length;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (left === 0) {
        controller.close();
        return;
      }
      const chunk = await reader.some(Math.min(left, BODY_CHUNK));
      if (chunk === null) throw new Http1Error(`the body ended ${left} bytes early`);
      left -= chunk.length;
      controller.enqueue(chunk);
    },
  });
}

function responseBody(
  reader: ByteReader,
  status: number,
  headers: Headers,
): ReadableStream<Uint8Array> | null {
  if (bodiless(status)) return null;
  if (headers.get('transfer-encoding')?.toLowerCase().includes('chunked')) {
    return chunkedBody(reader);
  }
  const length = headers.get('content-length');
  if (length !== null) {
    const size = Number(length);
    if (!Number.isInteger(size) || size < 0) throw new Http1Error(`bad content-length: ${length}`);
    return size === 0 ? null : countedBody(reader, size);
  }
  // Neither framing header: the body runs until the connection closes.
  return reader.rest();
}

/** Writes a streamed body as RFC 9112 chunks, ending with the empty one. */
async function writeChunked(writer: ByteWriter, body: ReadableStream<Uint8Array>): Promise<void> {
  const encoder = new TextEncoder();
  const source = body.getReader();
  for (;;) {
    const { value, done } = await source.read();
    if (done) break;
    // An empty chunk would read as the end of the body.
    if (value.byteLength === 0) continue;
    await writer.write(encoder.encode(`${value.byteLength.toString(16)}${CRLF}`));
    await writer.write(value);
    await writer.write(encoder.encode(CRLF));
  }
  await writer.write(encoder.encode(`0${CRLF}${CRLF}`));
}

export interface Http1Options {
  /**
   * Send the body as it arrives, in chunks, instead of reading it into memory
   * first to state its length. For uploads too large to hold; a server that
   * refuses chunked requests will answer 411.
   */
  streamBody?: boolean | undefined;
  /** Decoders beyond gzip and deflate; see `Decoders`. */
  decoders?: Decoders | undefined;
  /** The order to write headers in, as `arrange` takes it; left out, as given. */
  headerOrder?: readonly string[] | undefined;
}

/**
 * Sends one request over `socket` and returns the answer, its body still
 * streaming. `socket` is spent afterwards, and closing it is the caller's job —
 * it owns whatever the tunnel is made of.
 */
export async function http1Fetch(
  socket: Http1Socket,
  request: Request,
  { streamBody = false, decoders = {}, headerOrder }: Http1Options = {},
): Promise<Response> {
  const url = new URL(request.url);
  const writer = new ByteWriter(socket.writable);

  if (streamBody && request.body !== null) {
    const head = requestHead(
      url,
      request.method,
      request.headers,
      'chunked',
      decoders,
      headerOrder,
    );
    await writer.write(new TextEncoder().encode(head));
    await writeChunked(writer, request.body);
  } else {
    // Buffering keeps the request a plain Content-Length one, which every
    // server accepts, and costs nothing for a body that was in memory anyway.
    const body = request.body === null ? null : new Uint8Array(await request.arrayBuffer());
    const head = requestHead(
      url,
      request.method,
      request.headers,
      body?.byteLength ?? null,
      decoders,
      headerOrder,
    );
    await writer.write(new TextEncoder().encode(head));
    if (body && body.byteLength > 0) await writer.write(body);
  }
  writer.release();

  const reader = new ByteReader(socket.readable);
  const { status, statusText } = statusLine(await reader.line());
  const headers = await readHeaders(reader);
  const answer = responseBody(reader, status, headers);

  for (const name of HOP_BY_HOP) headers.delete(name);
  const plain = answer === null ? null : decompressed(answer, headers, decoders);
  return new Response(plain, { status, statusText, headers });
}
