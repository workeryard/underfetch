/**
 * Undoing the encoding a server applied.
 *
 * Both HTTP/1.1 and HTTP/2 need this, and only one of them used to have it:
 * a profile negotiates HTTP/2, so the path most requests take was handing
 * back gzip bytes with `content-encoding` still set, while the same request
 * over HTTP/1.1 came back as text.
 */

/**
 * What `DecompressionStream` understands, by the name the header uses. Written
 * as plain strings rather than `CompressionFormat`, which the DOM lib defines
 * and the Workers types do not — a library should typecheck in either.
 */
const FORMATS: Record<string, 'gzip' | 'deflate'> = {
  gzip: 'gzip',
  'x-gzip': 'gzip',
  deflate: 'deflate',
};

/**
 * Decoders the runtime has beyond `DecompressionStream`, by the name the
 * header uses — `br` and `zstd`, where the platform offers them. Each call
 * makes a fresh one, since a decoder holds the state of one body.
 */
export type Decoders = Readonly<Record<string, () => TransformStream<Uint8Array, Uint8Array>>>;

/** What `Accept-Encoding` says when nobody said anything. */
export function defaultAcceptEncoding(decoders: Decoders = {}): string {
  return ['gzip', 'deflate', ...Object.keys(decoders)].join(', ');
}

/**
 * `value` less every encoding we could not undo, order kept. A browser's
 * `gzip, deflate, br, zstd` goes out whole where brotli and zstd can be read,
 * and as `gzip, deflate` where they cannot: asking for an answer we cannot
 * read is how a request breaks.
 */
export function acceptable(value: string, decoders: Decoders = {}): string {
  return value
    .split(',')
    .map((token) => token.trim())
    .filter((token) => {
      const name = token.split(';')[0]!.trim().toLowerCase();
      return name === 'identity' || name in FORMATS || name in decoders;
    })
    .join(', ');
}

/**
 * Undoes the encoding the server applied. Content-Length describes the
 * compressed bytes, so it stops being true here and is dropped with it.
 */
export function decompressed(
  body: ReadableStream<Uint8Array>,
  headers: Headers,
  decoders: Decoders = {},
): ReadableStream<Uint8Array> {
  const encoding = headers.get('content-encoding')?.trim().toLowerCase();
  if (encoding === undefined) return body;
  const own = Object.hasOwn(decoders, encoding) ? decoders[encoding] : undefined;
  const format = FORMATS[encoding];
  if (own === undefined && format === undefined) return body;
  headers.delete('content-encoding');
  headers.delete('content-length');
  if (own !== undefined) return body.pipeThrough(own());
  // `DecompressionStream` is typed as taking any BufferSource, which is wider
  // than the Uint8Array stream we hand it and narrower than what it gives back.
  return body.pipeThrough(
    new DecompressionStream(format!) as unknown as TransformStream<Uint8Array, Uint8Array>,
  );
}

/** The part of a Node-style zlib stream a decoder needs. */
interface ZlibStream {
  write(chunk: Uint8Array, done: (error?: Error | null) => void): boolean;
  end(): void;
  on(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
  on(event: 'error', listener: (error: Error) => void): unknown;
}

/** The part of a Node-style `zlib` module these decoders use. */
export interface ZlibModule {
  createBrotliDecompress?: (() => ZlibStream) | undefined;
  createZstdDecompress?: (() => ZlibStream) | undefined;
}

/** A Node-style zlib stream, as the Web stream a body is piped through. */
function fromZlib(make: () => ZlibStream): () => TransformStream<Uint8Array, Uint8Array> {
  return () => {
    const zlib = make();
    let ended: Promise<void>;
    return new TransformStream<Uint8Array, Uint8Array>({
      start(controller) {
        // A Buffer is a Uint8Array over a pooled ArrayBuffer; copying keeps
        // the pool out of what the caller is handed.
        zlib.on('data', (chunk) => controller.enqueue(new Uint8Array(chunk)));
        ended = new Promise((resolve, reject) => {
          zlib.on('end', resolve);
          zlib.on('error', (error) => {
            controller.error(error);
            reject(error);
          });
        });
        // A failure is also reported to whichever write or flush is waiting.
        ended.catch(() => undefined);
      },
      transform(chunk) {
        return new Promise((resolve, reject) => {
          zlib.write(chunk, (error) => (error ? reject(error) : resolve()));
        });
      },
      flush() {
        zlib.end();
        return ended;
      },
    });
  };
}

/**
 * Brotli and zstd from a Node-style `zlib`, whichever it has. Workers carry
 * one on a recent compatibility date; Node has had both since 22.15.
 */
export function zlibDecoders(zlib: ZlibModule | undefined): Decoders {
  const out: Record<string, () => TransformStream<Uint8Array, Uint8Array>> = {};
  if (zlib?.createBrotliDecompress) out.br = fromZlib(zlib.createBrotliDecompress.bind(zlib));
  if (zlib?.createZstdDecompress) out.zstd = fromZlib(zlib.createZstdDecompress.bind(zlib));
  return out;
}
