/**
 * A small HTTP/1.1 client for a socket we opened ourselves.
 *
 * `fetch()` cannot ride an existing socket, so a tunnelled request has to be
 * written by hand. A connection carries one request at a time and is kept
 * alive, as a browser's is, for the next once an answer has been read to its
 * end; the body streams — an answer token by token is the whole point of
 * routing chat through here.
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
  constructor(
    message: string,
    /**
     * Nothing came back on a connection that had carried a request before:
     * the server had hung up on it while it sat idle, so the request was
     * never acted on and may be sent again on a new one.
     */
    readonly unprocessed = false,
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
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
  // Chrome writes Connection straight after Host; no other browser's
  // HTTP/1.1 order has been measured.
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${url.host}`, 'Connection: keep-alive'];
  if (!headers.has('user-agent')) lines.push(`User-Agent: ${USER_AGENT}`);
  for (const [name, value] of order ? arrange(headers, order) : headers) {
    if (hopByHop(name)) continue;
    if (name.toLowerCase() === 'host' || name.toLowerCase() === 'content-length') continue;
    lines.push(`${name}: ${value}`);
  }
  if (framing === 'chunked') lines.push('Transfer-Encoding: chunked');
  else if (framing !== null) lines.push(`Content-Length: ${framing}`);
  // Only what can be undone is asked for: brotli and zstd only where the
  // runtime has a decoder for them.
  if (!headers.has('accept-encoding')) {
    lines.push(`Accept-Encoding: ${defaultAcceptEncoding(decoders)}`);
  }
  return `${lines.join(CRLF)}${CRLF}${CRLF}`;
}

function statusLine(line: string): { status: number; statusText: string; minor: number } {
  const match = /^HTTP\/1\.([01]) (\d{3})(?: (.*))?$/.exec(line);
  if (!match) throw new Http1Error(`the server did not answer with HTTP/1.1: ${line.slice(0, 80)}`);
  return { status: Number(match[2]), statusText: match[3] ?? '', minor: Number(match[1]) };
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

export interface Http1Exchange {
  response: Response;
  /**
   * Settles once the answer has been read to its end, cancelled or cut off:
   * true when the connection can carry another request.
   */
  done: Promise<boolean>;
}

/**
 * Reports how a body ended: read to its end, or not. A connection whose body
 * was left half-read has the rest still coming down it and is spent.
 */
function reporting(
  body: ReadableStream<Uint8Array>,
  ended: (whole: boolean) => void,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          const { value, done } = await reader.read();
          if (done) {
            ended(true);
            controller.close();
            return;
          }
          controller.enqueue(value);
        } catch (error) {
          ended(false);
          throw error;
        }
      },
      cancel(reason) {
        ended(false);
        return reader.cancel(reason);
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * An HTTP/1.1 connection: one request at a time, each answered in full
 * before the next goes out. The reader lives as long as the connection,
 * since what it has buffered past one answer belongs to the next.
 */
export class Http1Connection {
  readonly #socket: Http1Socket;
  readonly #reader: ByteReader;
  #carried = 0;

  constructor(socket: Http1Socket) {
    this.#socket = socket;
    this.#reader = new ByteReader(socket.readable);
  }

  /** How many requests it has sent. */
  get carried(): number {
    return this.#carried;
  }

  /** Sends `request` and returns the answer, its body still streaming. */
  async exchange(request: Request, options: Http1Options = {}): Promise<Http1Exchange> {
    const reused = this.#carried > 0;
    this.#carried += 1;
    try {
      await this.#send(request, options);
    } catch (error) {
      // A write that fails on a kept connection never reached a server.
      if (reused) throw new Http1Error('the kept connection was closed', true, { cause: error });
      throw error;
    }

    let line: string;
    try {
      line = await this.#reader.line();
    } catch (error) {
      if (reused && this.#reader.exhausted) {
        throw new Http1Error('the server had closed the kept connection', true, { cause: error });
      }
      throw error;
    }
    const { status, statusText, minor } = statusLine(line);
    const headers = await readHeaders(this.#reader);
    const answer = responseBody(this.#reader, status, headers);
    // HTTP/1.0 closes unless asked not to; 1.1 keeps unless told it won't.
    const said = headers.get('connection')?.toLowerCase() ?? '';
    const kept =
      (minor === 1 ? !/\bclose\b/.test(said) : /\bkeep-alive\b/.test(said)) &&
      // A body that runs until the connection closes leaves nothing to keep.
      (answer === null || headers.has('content-length') || headers.has('transfer-encoding'));

    for (const name of HOP_BY_HOP) headers.delete(name);
    let finish: (reusable: boolean) => void = () => undefined;
    const done = new Promise<boolean>((resolve) => (finish = resolve));
    if (answer === null) {
      finish(kept);
      return { response: new Response(null, { status, statusText, headers }), done };
    }
    const tracked = reporting(answer, (whole) => finish(whole && kept));
    const plain = decompressed(tracked, headers, options.decoders ?? {});
    return { response: new Response(plain, { status, statusText, headers }), done };
  }

  async #send(
    request: Request,
    { streamBody = false, decoders = {}, headerOrder }: Http1Options,
  ): Promise<void> {
    const url = new URL(request.url);
    const writer = new ByteWriter(this.#socket.writable);
    try {
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
    } finally {
      writer.release();
    }
  }
}

/**
 * Sends one request over `socket` and returns the answer, its body still
 * streaming. `socket` is spent afterwards, and closing it is the caller's job —
 * it owns whatever the tunnel is made of.
 */
export async function http1Fetch(
  socket: Http1Socket,
  request: Request,
  options: Http1Options = {},
): Promise<Response> {
  return (await new Http1Connection(socket).exchange(request, options)).response;
}
