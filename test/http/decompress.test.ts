import { describe, expect, it } from 'vitest';
import { http1Fetch } from '../../src/http/http1';
import type { Http1Socket } from '../../src/http/http1';

async function gzipped(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** A server whose answer is assembled from a head and raw body bytes. */
function serving(head: string, body: Uint8Array): { socket: Http1Socket; sent: () => string } {
  const written: number[] = [];
  const headBytes = new TextEncoder().encode(head);
  const answer = new Uint8Array(headBytes.length + body.length);
  answer.set(headBytes);
  answer.set(body, headBytes.length);
  return {
    socket: {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(answer);
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
    },
    sent: () => new TextDecoder().decode(new Uint8Array(written)),
  };
}

describe('content encoding', () => {
  it('asks only for what it can undo', async () => {
    const { socket, sent } = serving(
      'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n',
      new TextEncoder().encode('hi'),
    );
    await http1Fetch(socket, new Request('https://example.com/'));
    // Brotli is not in DecompressionStream, so it must not be offered.
    expect(sent()).toContain('Accept-Encoding: gzip, deflate\r\n');
    expect(sent()).not.toContain('br');
  });

  it('unzips a gzipped answer and stops claiming it is encoded', async () => {
    const body = await gzipped('the quick brown fox');
    const { socket } = serving(
      `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${body.length}\r\n\r\n`,
      body,
    );

    const response = await http1Fetch(socket, new Request('https://example.com/'));

    expect(await response.text()).toBe('the quick brown fox');
    expect(response.headers.get('content-encoding')).toBeNull();
    // The length described the compressed bytes, so it is no longer true.
    expect(response.headers.get('content-length')).toBeNull();
  });

  it('leaves an encoding it does not know alone', async () => {
    const raw = new TextEncoder().encode('compressed by something else');
    const { socket } = serving(
      `HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: ${raw.length}\r\n\r\n`,
      raw,
    );

    const response = await http1Fetch(socket, new Request('https://example.com/'));
    expect(response.headers.get('content-encoding')).toBe('br');
    expect(await response.text()).toBe('compressed by something else');
  });

  it('honours an Accept-Encoding the caller set', async () => {
    const { socket, sent } = serving(
      'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n',
      new Uint8Array(),
    );
    await http1Fetch(
      socket,
      new Request('https://example.com/', { headers: { 'accept-encoding': 'identity' } }),
    );
    expect(sent()).toContain('accept-encoding: identity\r\n');
    expect(sent()).not.toContain('gzip');
  });
});
