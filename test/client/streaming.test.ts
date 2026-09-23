import { describe, expect, it } from 'vitest';
import { followRedirects } from '../../src/client/redirects';
import { Hpack } from '../../src/http/h2/hpack';
import { http2Fetch } from '../../src/http/h2/connection';
import { encodeFrame, Flags, FrameType, PREFACE } from '../../src/http/h2/frames';
import { http1Fetch, type Http1Socket } from '../../src/http/http1';

/**
 * Uploads that are sent as they arrive, never held whole in memory, and the
 * one thing that follows from that: such a body cannot be sent twice.
 */

const text = (s: string) => new TextEncoder().encode(s);

/** A body that arrives in pieces and records how much of it has been read. */
function pieces(...parts: string[]) {
  let read = 0;
  // No queue of its own, so a pull only happens when something reads.
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        const next = parts[read++];
        if (next === undefined) controller.close();
        else controller.enqueue(text(next));
      },
    },
    { highWaterMark: 0 },
  );
  return { stream, read: () => read };
}

const post = (body: ReadableStream<Uint8Array>, url = 'https://example.com/upload') =>
  new Request(url, { method: 'POST', body, duplex: 'half' } as RequestInit);

describe('a streamed upload over HTTP/1.1', () => {
  it('goes out in chunks, with no length announced', async () => {
    const written: number[] = [];
    const socket: Http1Socket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(text('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'));
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
    };
    const response = await http1Fetch(socket, post(pieces('hello ', '', 'world').stream), {
      streamBody: true,
    });
    expect(await response.text()).toBe('ok');

    const sent = new TextDecoder().decode(new Uint8Array(written));
    expect(sent).toContain('Transfer-Encoding: chunked\r\n');
    expect(sent).not.toContain('Content-Length');
    // The empty piece is skipped: written, it would end the body early.
    expect(sent.endsWith('\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n')).toBe(true);
  });
});

/** Splits what was written into frames, after the preface. */
function framesIn(written: number[]) {
  const data = new Uint8Array(written);
  const view = new DataView(data.buffer);
  const out: { type: number; flags: number; payload: Uint8Array }[] = [];
  for (let at = PREFACE.length; at + 9 <= data.length;) {
    const length = (data[at]! << 16) | view.getUint16(at + 1);
    out.push({
      type: data[at + 3]!,
      flags: data[at + 4]!,
      payload: data.subarray(at + 9, at + 9 + length),
    });
    at += 9 + length;
  }
  return out;
}

function h2Server() {
  const written: number[] = [];
  const ok = encodeFrame(
    FrameType.Headers,
    Flags.EndHeaders | Flags.EndStream,
    1,
    new Hpack().encode([[':status', '200']]),
  );
  return {
    socket: {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encodeFrame(FrameType.Settings, 0, 0, new Uint8Array(0)));
          controller.enqueue(ok);
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
    },
    data: () => framesIn(written).filter((f) => f.type === FrameType.Data),
  };
}

describe('a streamed upload over HTTP/2', () => {
  it('sends each piece as it comes, ending the stream on the last', async () => {
    const server = h2Server();
    await http2Fetch(server.socket, post(pieces('hello ', 'world').stream), undefined, {
      streamBody: true,
    });

    const data = server.data();
    expect(data.map((f) => new TextDecoder().decode(f.payload))).toEqual(['hello ', 'world']);
    expect(data.map((f) => f.flags & Flags.EndStream)).toEqual([0, Flags.EndStream]);
  });

  it('still ends a stream that turned out empty', async () => {
    const server = h2Server();
    await http2Fetch(server.socket, post(pieces().stream), undefined, { streamBody: true });

    const data = server.data();
    expect(data).toHaveLength(1);
    expect(data[0]!.payload.length).toBe(0);
    expect(data[0]!.flags & Flags.EndStream).toBe(Flags.EndStream);
  });
});

describe('redirects with a streamed body', () => {
  const answer = (status: number, location = '/elsewhere') =>
    new Response(null, { status, headers: { location } });

  it('hands a 307 back rather than read the stream to send it again', async () => {
    const body = pieces('big');
    const seen: string[] = [];
    const response = await followRedirects(
      post(body.stream),
      (request) => {
        seen.push(request.url);
        return Promise.resolve(answer(307));
      },
      {},
      false,
    );
    expect(response.status).toBe(307);
    expect(seen).toHaveLength(1);
    // Nothing read it into memory on the way.
    expect(body.read()).toBe(0);
  });

  it('follows a 303, which asks for a GET and no body', async () => {
    const seen: string[] = [];
    const response = await followRedirects(
      post(pieces('big').stream),
      (request) => {
        seen.push(`${request.method} ${request.url}`);
        return Promise.resolve(seen.length === 1 ? answer(303) : new Response('done'));
      },
      {},
      false,
    );
    expect(await response.text()).toBe('done');
    expect(seen).toEqual(['POST https://example.com/upload', 'GET https://example.com/elsewhere']);
  });
});
