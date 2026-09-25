/**
 * HTTP Digest authentication (RFC 7616), as curl does it: send the request
 * without credentials, read the challenge from the 401, and send it again
 * with the answer. So it costs a round trip, and a body that can be sent only
 * once gets the 401 back rather than a second attempt.
 *
 * MD5 is written out here because it is what nearly every server asks for
 * and Web Crypto does not have it — Workers do, but only as an extension, and
 * nothing below `workers/` may lean on one runtime. SHA-256 comes from Web
 * Crypto. SHA-512-256 and `qop=auth-int` are refused by name.
 */

import { ApiError } from './request';

export interface DigestCredentials {
  username: string;
  password: string;
}

/** One challenge from a `WWW-Authenticate` header: its scheme and parameters. */
export interface Challenge {
  scheme: string;
  params: Map<string, string>;
}

/**
 * Every challenge in a `WWW-Authenticate` value. A server may offer several,
 * and `Headers` joins repeated fields with commas, so a comma can end a
 * parameter or a whole challenge; a bare token is what starts a new one.
 */
export function parseChallenges(value: string): Challenge[] {
  const out: Challenge[] = [];
  let at = 0;
  const skip = () => {
    while (at < value.length && /[\s,]/.test(value[at]!)) at++;
  };
  const token = () => {
    const start = at;
    while (at < value.length && !/[\s,=]/.test(value[at]!)) at++;
    return value.slice(start, at);
  };

  for (skip(); at < value.length; skip()) {
    const name = token();
    if (name === '') {
      at++;
      continue;
    }
    while (at < value.length && value[at] === ' ') at++;
    if (value[at] !== '=' || out.length === 0) {
      out.push({ scheme: name.toLowerCase(), params: new Map() });
      // A scheme may be followed by its first parameter on the same breath.
      continue;
    }
    at++;
    while (at < value.length && value[at] === ' ') at++;
    let param: string;
    if (value[at] === '"') {
      param = '';
      for (at++; at < value.length && value[at] !== '"'; at++) {
        if (value[at] === '\\') at++;
        param += value[at] ?? '';
      }
      at++;
    } else {
      // A token68 such as `Negotiate abc==` ends up here too, harmlessly.
      const start = at;
      while (at < value.length && value[at] !== ',') at++;
      param = value.slice(start, at).trim();
    }
    out.at(-1)!.params.set(name.toLowerCase(), param);
  }
  return out;
}

/* MD5 (RFC 1321), for Digest only. */

const SHIFTS = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const SINES = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32));

export function md5(bytes: Uint8Array): Uint8Array {
  const padded = new Uint8Array(((bytes.length + 8) >>> 6) * 64 + 64);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, (bytes.length * 8) >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bytes.length / 2 ** 29), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  for (let block = 0; block < padded.length; block += 64) {
    const word = (i: number) => view.getUint32(block + i * 4, true);
    let [a, b, c, d] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      const round = i >>> 4;
      const f =
        round === 0
          ? (b & c) | (~b & d)
          : round === 1
            ? (d & b) | (~d & c)
            : round === 2
              ? b ^ c ^ d
              : c ^ (b | ~d);
      const g =
        round === 0
          ? i
          : round === 1
            ? (5 * i + 1) & 15
            : round === 2
              ? (3 * i + 5) & 15
              : (7 * i) & 15;
      const sum = (a + f + SINES[i]! + word(g)) | 0;
      const shift = SHIFTS[round * 4 + (i & 3)]!;
      [a, d, c] = [d, c, b];
      b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
    }
    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => outView.setUint32(i * 4, v, true));
  return out;
}

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

type Hash = (text: string) => Promise<string>;

const HASHES: Record<string, Hash> = {
  md5: (text) => Promise.resolve(hex(md5(new TextEncoder().encode(text)))),
  'sha-256': async (text) =>
    hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))),
};

export interface DigestInput {
  challenge: Challenge;
  credentials: DigestCredentials;
  method: string;
  /** The request target as sent: path and query. */
  uri: string;
  /** Which request this is under the same nonce, from 1. */
  count: number;
  /** Given in tests; otherwise fresh and random. */
  cnonce?: string | undefined;
}

/** The `Authorization` value that answers `challenge`. */
export async function digestAuthorization({
  challenge,
  credentials,
  method,
  uri,
  count,
  cnonce = hex(crypto.getRandomValues(new Uint8Array(16))),
}: DigestInput): Promise<string> {
  const { params } = challenge;
  const realm = params.get('realm') ?? '';
  const nonce = params.get('nonce');
  if (nonce === undefined) throw new ApiError('the Digest challenge carries no nonce');

  const algorithm = params.get('algorithm') ?? 'MD5';
  const lower = algorithm.toLowerCase();
  const session = lower.endsWith('-sess');
  const hash = HASHES[session ? lower.slice(0, -5) : lower];
  if (hash === undefined) throw new ApiError(`Digest algorithm ${algorithm} is not supported`);

  // A server may offer several; only `auth` is spoken here.
  const offered = params
    .get('qop')
    ?.split(',')
    .map((q) => q.trim().toLowerCase());
  if (offered !== undefined && !offered.includes('auth')) {
    throw new ApiError(`Digest qop ${params.get('qop')} is not supported`);
  }
  const qop = offered === undefined ? undefined : 'auth';
  const nc = count.toString(16).padStart(8, '0');

  let ha1 = await hash(`${credentials.username}:${realm}:${credentials.password}`);
  if (session) ha1 = await hash(`${ha1}:${nonce}:${cnonce}`);
  const ha2 = await hash(`${method}:${uri}`);
  const response = await hash(
    qop === undefined ? `${ha1}:${nonce}:${ha2}` : `${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`,
  );

  const quote = (text: string) => `"${text.replace(/["\\]/g, '\\$&')}"`;
  const fields = [
    `username=${quote(credentials.username)}`,
    `realm=${quote(realm)}`,
    `nonce=${quote(nonce)}`,
    `uri=${quote(uri)}`,
    `algorithm=${algorithm}`,
    `response=${quote(response)}`,
  ];
  if (qop !== undefined) fields.push(`qop=${qop}`, `nc=${nc}`, `cnonce=${quote(cnonce)}`);
  const opaque = params.get('opaque');
  if (opaque !== undefined) fields.push(`opaque=${quote(opaque)}`);
  return `Digest ${fields.join(', ')}`;
}

/**
 * Sends `request` through `send`, answering a Digest challenge once. Only
 * where `origin` matches: credentials never follow a redirect to another host.
 * `replayable` is false for a body that can be sent only once, which then
 * comes back as the 401.
 */
export async function withDigest(
  request: Request,
  send: (request: Request) => Promise<Response>,
  credentials: DigestCredentials,
  origin: string,
  replayable: boolean,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.origin !== origin || request.headers.has('authorization')) return send(request);
  const spare = replayable ? request.clone() : null;
  const response = await send(request);
  if (response.status !== 401 || spare === null) return response;

  const challenge = parseChallenges(response.headers.get('www-authenticate') ?? '').find(
    (c) => c.scheme === 'digest',
  );
  if (challenge === undefined) return response;
  await response.body?.cancel();

  const headers = new Headers(spare.headers);
  headers.set(
    'authorization',
    await digestAuthorization({
      challenge,
      credentials,
      method: spare.method,
      uri: `${url.pathname}${url.search}`,
      count: 1,
    }),
  );
  return send(new Request(spare, { headers }));
}
