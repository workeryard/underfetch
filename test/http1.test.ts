import { describe, expect, it } from 'vitest';
import { http1Fetch } from '../src/http1';
import type { Http1Socket } from '../src/http1';

/** A socket that replays a canned answer and records the request written to it. */
function fakeServer(answer: string | number[]): { socket: Http1Socket; sent: () => string } {
  const written: number[] = [];
  const bytes = typeof answer === 'string' ? [...new TextEncoder().encode(answer)] : answer;
  return {
    socket: {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(bytes));
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

/** A server that hands out its body a piece at a time, as a streaming one does. */
function drip(pieces: string[]): Http1Socket {
  return {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        for (const piece of pieces) controller.enqueue(new TextEncoder().encode(piece));
        controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>(),
  };
}

const OK = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi';

describe('http1', () => {
  it('writes a request line, a host and a length', async () => {
    const { socket, sent } = fakeServer(OK);
    const response = await http1Fetch(
      socket,
      new Request('https://api.groq.com/openai/v1/chat/completions?a=1', {
        method: 'POST',
        headers: { authorization: 'Bearer gsk', 'content-type': 'application/json' },
        body: '{"model":"x"}',
      }),
    );

    const wire = sent();
    expect(wire).toContain('POST /openai/v1/chat/completions?a=1 HTTP/1.1\r\n');
    expect(wire).toContain('Host: api.groq.com\r\n');
    expect(wire).toContain('authorization: Bearer gsk\r\n');
    expect(wire).toContain('Content-Length: 13\r\n');
    expect(wire).toContain('Connection: close\r\n');
    expect(wire.endsWith('{"model":"x"}')).toBe(true);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('hi');
  });

  it('decodes a chunked body and drops the framing headers', async () => {
    const { socket } = fakeServer(
      'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n',
    );
    const response = await http1Fetch(socket, new Request('https://example.com/'));

    expect(await response.text()).toBe('hello world');
    expect(response.headers.get('transfer-encoding')).toBeNull();
  });

  it('gives a streamed answer out piece by piece, not in one lump', async () => {
    const socket = drip([
      'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n',
      '8\r\ndata: a\n\r\n',
      '8\r\ndata: b\n\r\n',
      '0\r\n\r\n',
    ]);
    const response = await http1Fetch(socket, new Request('https://example.com/'));

    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const first = await reader.read();
    // The second event is still on the wire; the first must not wait for it.
    expect(new TextDecoder().decode(first.value)).toBe('data: a\n');
    const second = await reader.read();
    expect(new TextDecoder().decode(second.value)).toBe('data: b\n');
    expect((await reader.read()).done).toBe(true);
  });

  it('keeps a status with no body empty', async () => {
    const { socket } = fakeServer('HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\n');
    const response = await http1Fetch(socket, new Request('https://example.com/'));
    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
  });

  it('reads a body that ends only when the connection does', async () => {
    const { socket } = fakeServer('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nall of it');
    const response = await http1Fetch(socket, new Request('https://example.com/'));
    expect(await response.text()).toBe('all of it');
  });

  it('keeps every value of a repeated header', async () => {
    const { socket } = fakeServer(
      'HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n',
    );
    const response = await http1Fetch(socket, new Request('https://example.com/'));
    expect(response.headers.getSetCookie()).toEqual(['a=1', 'b=2']);
  });

  it('refuses an answer that is not HTTP', async () => {
    const portal = fakeServer('<html>a captive portal</html>\r\n\r\n');
    await expect(http1Fetch(portal.socket, new Request('https://example.com/'))).rejects.toThrow(
      /did not answer with HTTP/,
    );

    // A proxy that hangs up mid-line fails too, just with the reader's words.
    const cut = fakeServer('HTTP/1.1 200');
    await expect(http1Fetch(cut.socket, new Request('https://example.com/'))).rejects.toThrow(
      /stream ended/,
    );
  });
});
