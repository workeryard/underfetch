import { describe, expect, it } from 'vitest';
import { ApiError, buildRequest, followRedirects } from '../src/api';
import { Session } from '../src/session';
import type { ByteSocket, Dial } from '../src/socket';
import type { TlsSession } from '../src/tls';

class Passthrough implements TlsSession {
  handshaking = false;
  #plain: number[] = [];
  #out: number[] = [];
  receive(data: Uint8Array): number {
    this.#plain.push(...data);
    return data.length;
  }
  outgoing(): Uint8Array {
    const out = new Uint8Array(this.#out);
    this.#out = [];
    return out;
  }
  send(data: Uint8Array): void {
    this.#out.push(...data);
  }
  plaintext(): Uint8Array {
    const plain = new Uint8Array(this.#plain);
    this.#plain = [];
    return plain;
  }
  close(): void {}
}

/** A server that answers each connection from a queue of canned replies. */
function net(replies: string[]) {
  const dialled: string[] = [];
  const sent: string[] = [];
  let next = 0;
  const dial: Dial = (hostname, port) => {
    dialled.push(`${hostname}:${port}`);
    const answer = replies[Math.min(next++, replies.length - 1)]!;
    const written: number[] = [];
    const socket: ByteSocket = {
      readable: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(answer));
          controller.close();
        },
      }),
      writable: new WritableStream<Uint8Array>({
        write(chunk) {
          written.push(...chunk);
        },
      }),
      close: () => {
        sent.push(new TextDecoder().decode(new Uint8Array(written)));
        return Promise.resolve();
      },
    };
    return Promise.resolve(socket);
  };
  return { dial, dialled, sent };
}

const OK = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok';
const moved = (to: string, status = 302) =>
  `HTTP/1.1 ${status} Moved\r\nLocation: ${to}\r\nContent-Length: 0\r\n\r\n`;

const sessionOn = (wire: ReturnType<typeof net>, defaults = {}) =>
  new Session({ dial: wire.dial, tls: () => new Passthrough(), ...defaults });

describe('building a request', () => {
  it('merges query parameters into the url it was given', () => {
    const request = buildRequest('https://api.example.com/v1?a=1', {
      params: { b: 2, c: true },
    });
    const url = new URL(request.url);
    expect(url.searchParams.getAll('a')).toEqual(['1']);
    expect(url.searchParams.get('b')).toBe('2');
    expect(url.searchParams.get('c')).toBe('true');
  });

  it('resolves a path against the session base', () => {
    const request = buildRequest('/v1/models', undefined, 'https://api.example.com');
    expect(request.url).toBe('https://api.example.com/v1/models');
  });

  it('sends json with the content type it implies', async () => {
    const request = buildRequest('https://example.com/', {
      method: 'POST',
      json: { model: 'x' },
    });
    expect(request.headers.get('content-type')).toBe('application/json');
    expect(await request.text()).toBe('{"model":"x"}');
  });

  it('sends a form as urlencoded', async () => {
    const request = buildRequest('https://example.com/', {
      method: 'POST',
      form: { grant_type: 'client_credentials' },
    });
    expect(request.headers.get('content-type')).toContain('x-www-form-urlencoded');
    expect(await request.text()).toBe('grant_type=client_credentials');
  });

  it('writes both kinds of authorization', () => {
    expect(
      buildRequest('https://e.com/', { auth: { bearer: 'sk-1' } }).headers.get('authorization'),
    ).toBe('Bearer sk-1');
    expect(
      buildRequest('https://e.com/', {
        auth: { username: 'ada', password: 'lovelace' },
      }).headers.get('authorization'),
    ).toBe(`Basic ${btoa('ada:lovelace')}`);
  });

  it('leaves a header the caller set alone', () => {
    const request = buildRequest('https://e.com/', {
      method: 'POST',
      json: { a: 1 },
      auth: { bearer: 'ignored' },
      headers: { 'content-type': 'application/problem+json', authorization: 'Bearer mine' },
    });
    expect(request.headers.get('content-type')).toBe('application/problem+json');
    expect(request.headers.get('authorization')).toBe('Bearer mine');
  });

  it('refuses two bodies at once', () => {
    expect(() => buildRequest('https://e.com/', { json: {}, form: {} })).toThrow(ApiError);
  });
});

describe('redirects', () => {
  it('follows one and reports where it ended', async () => {
    const wire = net([moved('https://example.com/second'), OK]);
    const response = await sessionOn(wire).get('https://example.com/first');

    expect(await response.text()).toBe('ok');
    expect(response.url).toBe('https://example.com/second');
    expect(wire.dialled).toHaveLength(2);
  });

  it('turns a 303 into a GET without the body', async () => {
    const wire = net([moved('https://example.com/done', 303), OK]);
    await (await sessionOn(wire).post('https://example.com/submit', { json: { a: 1 } })).text();

    expect(wire.sent[1]).toContain('GET /done HTTP/1.1');
    expect(wire.sent[1]).not.toContain('content-type');
  });

  it('keeps the method and body on a 307', async () => {
    const wire = net([moved('https://example.com/done', 307), OK]);
    await (await sessionOn(wire).post('https://example.com/submit', { json: { a: 1 } })).text();
    expect(wire.sent[1]).toContain('POST /done HTTP/1.1');
  });

  it('drops credentials when the host changes', async () => {
    const wire = net([moved('https://elsewhere.example/'), OK]);
    await (
      await sessionOn(wire).get('https://example.com/', { auth: { bearer: 'sk-secret' } })
    ).text();

    expect(wire.sent[0]).toContain('sk-secret');
    expect(wire.sent[1]).not.toContain('sk-secret');
  });

  it('stops when told not to follow', async () => {
    const wire = net([moved('https://example.com/second')]);
    const response = await sessionOn(wire).get('https://example.com/first', {
      allowRedirects: false,
    });

    expect(response.status).toBe(302);
    expect(wire.dialled).toHaveLength(1);
  });

  it('gives up rather than looping forever', async () => {
    const wire = net([moved('https://example.com/again')]);
    await expect(sessionOn(wire).get('https://example.com/', { maxRedirects: 3 })).rejects.toThrow(
      /gave up after 3/,
    );
  });

  it('is also available on its own, around any sender', async () => {
    const seen: string[] = [];
    const response = await followRedirects(new Request('https://example.com/one'), (request) => {
      seen.push(request.url);
      return Promise.resolve(
        seen.length === 1
          ? new Response(null, { status: 302, headers: { location: '/two' } })
          : new Response('done'),
      );
    });
    expect(seen).toEqual(['https://example.com/one', 'https://example.com/two']);
    expect(await response.text()).toBe('done');
  });
});

describe('session shortcuts', () => {
  it('takes paths once it knows the base', async () => {
    const wire = net([OK]);
    await (await sessionOn(wire, { baseUrl: 'https://api.example.com' }).get('/v1/models')).text();

    expect(wire.dialled).toEqual(['api.example.com:443']);
    expect(wire.sent[0]).toContain('GET /v1/models HTTP/1.1');
  });

  it('has a method for each verb', async () => {
    const wire = net([OK, OK, OK, OK, OK]);
    const session = sessionOn(wire, { baseUrl: 'https://e.com' });
    for (const call of [
      () => session.post('/a', { json: {} }),
      () => session.put('/b'),
      () => session.patch('/c'),
      () => session.del('/d'),
      () => session.head('/e'),
    ]) {
      await (await call()).text();
    }
    const methods = wire.sent.map((text) => text.slice(0, text.indexOf(' ')));
    expect(methods.sort()).toEqual(['DELETE', 'HEAD', 'PATCH', 'POST', 'PUT']);
  });
});
