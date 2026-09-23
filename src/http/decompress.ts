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
 * Undoes the encoding the server applied. Content-Length describes the
 * compressed bytes, so it stops being true here and is dropped with it.
 */
export function decompressed(
  body: ReadableStream<Uint8Array>,
  headers: Headers,
): ReadableStream<Uint8Array> {
  const encoding = headers.get('content-encoding')?.trim().toLowerCase();
  const format = encoding === undefined ? undefined : FORMATS[encoding];
  if (format === undefined) return body;
  headers.delete('content-encoding');
  headers.delete('content-length');
  // `DecompressionStream` is typed as taking any BufferSource, which is wider
  // than the Uint8Array stream we hand it and narrower than what it gives back.
  return body.pipeThrough(
    new DecompressionStream(format) as unknown as TransformStream<Uint8Array, Uint8Array>,
  );
}
