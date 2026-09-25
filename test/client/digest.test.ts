import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { digestAuthorization, md5, parseChallenges } from '../../src/client/digest';
import { Session } from '../../src/client/session';
import type { ByteSocket, Dial } from '../../src/net/socket';

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

describe('md5', () => {
  it('matches the RFC 1321 test suite', () => {
    const cases: [string, string][] = [
      ['', 'd41d8cd98f00b204e9800998ecf8427e'],
      ['a', '0cc175b9c0f1b6a831c399e269772661'],
      ['abc', '900150983cd24fb0d6963f7d28e17f72'],
      ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
      [
        '12345678901234567890123456789012345678901234567890123456789012345678901234567890',
        '57edf4a22be3c955ac49da2e2107b67a',
      ],
    ];
    for (const [text, want] of cases) expect(hex(md5(new TextEncoder().encode(text)))).toBe(want);
  });

  it('agrees with node at every length across the block boundaries', () => {
    for (let length = 0; length < 200; length++) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 31 + length) & 0xff);
      expect(hex(md5(bytes))).toBe(createHash('md5').update(bytes).digest('hex'));
    }
  });
});

describe('parseChallenges', () => {
  it('reads quoted and bare parameters, escapes included', () => {
    const [digest] = parseChallenges(
      'Digest realm="a \\"b\\", c", qop="auth,auth-int", algorithm=MD5, nonce="n1"',
    );
    expect(digest?.scheme).toBe('digest');
    expect(digest?.params.get('realm')).toBe('a "b", c');
    expect(digest?.params.get('qop')).toBe('auth,auth-int');
    expect(digest?.params.get('algorithm')).toBe('MD5');
    expect(digest?.params.get('nonce')).toBe('n1');
  });

  it('separates several challenges joined into one header', () => {
    const challenges = parseChallenges(
      'Basic realm="x", Digest realm="y", nonce="z", Bearer realm="w"',
    );
    expect(challenges.map((c) => c.scheme)).toEqual(['basic', 'digest', 'bearer']);
    expect(challenges[1]?.params.get('nonce')).toBe('z');
  });
});

describe('digestAuthorization', () => {
  // RFC 7616 §3.9.1, with the response values the RFC gives.
  const challenge = (algorithm: string) =>
    parseChallenges(
      `Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=${algorithm}, ` +
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", ' +
        'opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"',
    )[0]!;
  const input = (algorithm: string) => ({
    challenge: challenge(algorithm),
    credentials: { username: 'Mufasa', password: 'Circle of Life' },
    method: 'GET',
    uri: '/dir/index.html',
    count: 1,
    cnonce: 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ',
  });

  it('answers the RFC example with MD5', async () => {
    const value = await digestAuthorization(input('MD5'));
    expect(value).toContain('response="8ca523f5e9506fed4657c9700eebdbec"');
    expect(value).toContain('qop=auth, nc=00000001');
    expect(value).toContain('opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"');
  });

  it('answers the RFC example with SHA-256', async () => {
    const value = await digestAuthorization(input('SHA-256'));
    expect(value).toContain(
      'response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"',
    );
  });

  it('folds the nonces into the key for a -sess algorithm', async () => {
    const h = (text: string) => createHash('md5').update(text).digest('hex');
    const i = input('MD5-sess');
    const ha1 = h(
      `${h('Mufasa:http-auth@example.org:Circle of Life')}:${i.challenge.params.get('nonce')}:${i.cnonce}`,
    );
    const ha2 = h('GET:/dir/index.html');
    const want = h(`${ha1}:${i.challenge.params.get('nonce')}:00000001:${i.cnonce}:auth:${ha2}`);
    const value = await digestAuthorization(i);
    expect(value).toContain(`response="${want}"`);
    expect(value).toContain('algorithm=MD5-sess');
  });

  it('refuses what it cannot compute, by name', async () => {
    await expect(digestAuthorization(input('SHA-512-256'))).rejects.toThrow(/SHA-512-256/);
  });
});

/** A server answering each connection in turn, recording what each was sent. */
function server(answers: string[]) {
  const sent: string[] = [];
  const dial: Dial = () => {
    const answer = answers.shift() ?? 'HTTP/1.1 500 Nothing Left\r\nContent-Length: 0\r\n\r\n';
    const written: number[] = [];
    const index = sent.push('') - 1;
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
          sent[index] = new TextDecoder().decode(new Uint8Array(written));
        },
      }),
      close: () => Promise.resolve(),
    };
    return Promise.resolve(socket);
  };
  return { dial, sent };
}

const CHALLENGE =
  'HTTP/1.1 401 Unauthorized\r\n' +
  'WWW-Authenticate: Digest realm="me@example.com", nonce="abc", qop="auth", opaque="xyz"\r\n' +
  'Content-Length: 0\r\n\r\n';
const OK = 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok';

describe('Session with Digest', () => {
  const credentials = { username: 'u', password: 'p', type: 'digest' } as const;

  it('answers the challenge and sends the body again', async () => {
    const wire = server([CHALLENGE, OK]);
    const session = new Session({ dial: wire.dial, tls: () => undefined as never });

    const response = await session.post('http://example.com/private?x=1', {
      auth: credentials,
      json: { hello: 'world' },
    });

    expect(response.status).toBe(200);
    expect(wire.sent).toHaveLength(2);
    expect(wire.sent[0]).not.toContain('Authorization');
    expect(wire.sent[1]).toMatch(/authorization: Digest username="u", realm="me@example.com"/);
    expect(wire.sent[1]).toContain('uri="/private?x=1"');
    expect(wire.sent[1]).toContain('{"hello":"world"}');
  });

  it('hands back a 401 that offers no Digest', async () => {
    const wire = server([
      'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="x"\r\nContent-Length: 0\r\n\r\n',
    ]);
    const session = new Session({ dial: wire.dial, tls: () => undefined as never });

    const response = await session.get('http://example.com/', { auth: credentials });
    expect(response.status).toBe(401);
    expect(wire.sent).toHaveLength(1);
  });

  it('does not answer twice when the credentials are wrong', async () => {
    const wire = server([CHALLENGE, CHALLENGE, OK]);
    const session = new Session({ dial: wire.dial, tls: () => undefined as never });

    const response = await session.get('http://example.com/', { auth: credentials });
    expect(response.status).toBe(401);
    expect(wire.sent).toHaveLength(2);
  });

  it('keeps the credentials from a host a redirect leads to', async () => {
    const wire = server([
      'HTTP/1.1 302 Found\r\nLocation: http://elsewhere.example/\r\nContent-Length: 0\r\n\r\n',
      CHALLENGE,
    ]);
    const session = new Session({ dial: wire.dial, tls: () => undefined as never });

    const response = await session.get('http://example.com/', { auth: credentials });
    expect(response.status).toBe(401);
    expect(wire.sent).toHaveLength(2);
    expect(wire.sent[1]).not.toContain('Digest');
  });
});
