/**
 * Proving the fingerprint without asking anyone.
 *
 * A library that claims to look like Chrome should be able to show it, rather
 * than send its own handshake to a stranger's website and take their word for
 * it. Both fingerprints are deterministic functions of bytes we generate, so
 * both can be computed here: JA4 from the ClientHello, and the Akamai string
 * from the HTTP/2 settings.
 *
 * An external check is still worth doing now and then — it catches what this
 * cannot, such as the runtime rewriting something underneath us — but it is a
 * second opinion, not the only one.
 */

import type { Http2Profile } from '../http/h2/connection';
import { GREASE } from './grease';

export interface ClientHello {
  ciphers: number[];
  extensions: number[];
  signatureSchemes: number[];
  alpn: string[];
  /** True when a server name was sent, which JA4 records as `d` rather than `i`. */
  hasServerName: boolean;
  /** Supported groups, which JA3 reads and JA4 does not. */
  groups?: number[] | undefined;
  /** EC point formats, the last field of JA3. */
  pointFormats?: number[] | undefined;
  /** The key shares sent, as group and share length; neither JA3 nor JA4 reads them. */
  keyShares?: { group: number; length: number }[] | undefined;
}

const isGrease = (value: number) => (GREASE as readonly number[]).includes(value);
const hex = (value: number) => value.toString(16).padStart(4, '0');

export class VerifyError extends Error {
  override name = 'VerifyError';
}

/** Reads the fields a fingerprint is built from out of a ClientHello record. */
export function parseClientHello(record: Uint8Array): ClientHello {
  if (record.length < 45 || record[0] !== 0x16) {
    throw new VerifyError('that is not a TLS handshake record');
  }
  const view = new DataView(record.buffer, record.byteOffset, record.byteLength);
  // 5 bytes of record header, 4 of handshake header, 2 of version, 32 of random.
  let at = 5 + 4 + 2 + 32;
  at += 1 + record[at]!; // session id
  const cipherBytes = view.getUint16(at);
  at += 2;
  const ciphers: number[] = [];
  for (let i = 0; i < cipherBytes; i += 2) ciphers.push(view.getUint16(at + i));
  at += cipherBytes;
  at += 1 + record[at]!; // compression methods

  const extensionBytes = view.getUint16(at);
  at += 2;
  const end = at + extensionBytes;
  const extensions: number[] = [];
  let signatureSchemes: number[] = [];
  const alpn: string[] = [];
  let hasServerName = false;
  const groups: number[] = [];
  const pointFormats: number[] = [];
  const keyShares: { group: number; length: number }[] = [];

  while (at + 4 <= end) {
    const type = view.getUint16(at);
    const length = view.getUint16(at + 2);
    extensions.push(type);
    const body = at + 4;
    if (type === 0x000d) {
      const listBytes = view.getUint16(body);
      signatureSchemes = [];
      for (let i = 0; i < listBytes; i += 2) signatureSchemes.push(view.getUint16(body + 2 + i));
    } else if (type === 0x0010) {
      let cursor = body + 2;
      while (cursor < body + length) {
        const size = record[cursor]!;
        alpn.push(new TextDecoder().decode(record.subarray(cursor + 1, cursor + 1 + size)));
        cursor += 1 + size;
      }
    } else if (type === 0x0000) {
      hasServerName = true;
    } else if (type === 0x000a) {
      const listBytes = view.getUint16(body);
      for (let i = 0; i < listBytes; i += 2) groups.push(view.getUint16(body + 2 + i));
    } else if (type === 0x000b) {
      for (let i = 0; i < record[body]!; i++) pointFormats.push(record[body + 1 + i]!);
    } else if (type === 0x0033) {
      let cursor = body + 2;
      while (cursor + 4 <= body + length) {
        const share = { group: view.getUint16(cursor), length: view.getUint16(cursor + 2) };
        keyShares.push(share);
        cursor += 4 + share.length;
      }
    }
    at = body + length;
  }
  return {
    ciphers,
    extensions,
    signatureSchemes,
    alpn,
    hasServerName,
    groups,
    pointFormats,
    keyShares,
  };
}

const sha256 = async (text: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 12);
};

/**
 * JA4 as FoxIO defines it: a readable prefix, then a hash of the sorted cipher
 * list, then a hash of the sorted extension list and the signature algorithms
 * in the order they were sent. GREASE is stripped throughout, and server_name
 * and ALPN are counted but left out of the extension hash.
 */
export async function ja4(hello: ClientHello, transport: 't' | 'q' = 't'): Promise<string> {
  const ciphers = hello.ciphers.filter((c) => !isGrease(c)).map(hex);
  const extensions = hello.extensions.filter((e) => !isGrease(e));
  const hashed = extensions
    .filter((e) => e !== 0x0000 && e !== 0x0010)
    .map(hex)
    .sort();

  const alpn = hello.alpn[0] ?? '00';
  const short = alpn === '00' ? '00' : `${alpn[0]}${alpn[alpn.length - 1]}`;
  const count = (n: number) => Math.min(n, 99).toString().padStart(2, '0');
  const prefix = `${transport}13${hello.hasServerName ? 'd' : 'i'}${count(ciphers.length)}${count(
    extensions.length,
  )}${short}`;

  return [
    prefix,
    await sha256([...ciphers].sort().join(',')),
    await sha256(`${hashed.join(',')}_${hello.signatureSchemes.map(hex).join(',')}`),
  ].join('_');
}

/**
 * JA3, as Salesforce defines it: the TLS version, then ciphers, extensions,
 * groups and point formats, each in the order sent, GREASE left out. Unlike
 * JA4 it keeps extension order, so it tells shuffled Chrome hellos apart.
 */
export function ja3(hello: ClientHello): string {
  const list = (values: readonly number[] | undefined) =>
    (values ?? []).filter((v) => !isGrease(v)).join('-');
  return [
    771,
    list(hello.ciphers),
    list(hello.extensions),
    list(hello.groups),
    (hello.pointFormats ?? []).join('-'),
  ].join(',');
}

/**
 * The Akamai HTTP/2 fingerprint: settings, window update, priority frames and
 * pseudo-header order. Its usual companion hash is MD5, which WebCrypto does
 * not offer and which is no more informative than the string itself.
 */
export function akamai(profile: Http2Profile): string {
  const settings = profile.settings.map(([id, value]) => `${id}:${value}`).join(';');
  // No priority frames are sent, which this notation writes as a bare zero.
  return `${settings}|${profile.windowUpdate}|0|${profile.pseudoHeaderOrder.join(',')}`;
}

export interface Verdict {
  name: string;
  ja4: { got: string; want: string; ok: boolean };
  akamai: { got: string; want: string; ok: boolean };
  /** Present when the profile states a JA3 to match. */
  ja3?: { got: string; want: string; ok: boolean } | undefined;
  ok: boolean;
}

/**
 * Checks one profile against the fingerprints it claims. `hello` is a real
 * ClientHello from the TLS module, so this measures what goes on the wire
 * rather than what the profile says it would put there.
 */
export async function verifyProfile(
  name: string,
  profile: {
    http2: Http2Profile;
    expected: { ja4: string; akamai: string; ja3?: string | undefined };
  },
  hello: Uint8Array,
): Promise<Verdict> {
  const parsed = parseClientHello(hello);
  const got = {
    ja4: await ja4(parsed),
    akamai: akamai(profile.http2),
  };
  const wantJa3 = profile.expected.ja3;
  const ja3Check =
    wantJa3 === undefined
      ? undefined
      : { got: ja3(parsed), want: wantJa3, ok: ja3(parsed) === wantJa3 };
  const checked = {
    ja4: { got: got.ja4, want: profile.expected.ja4, ok: got.ja4 === profile.expected.ja4 },
    akamai: {
      got: got.akamai,
      want: profile.expected.akamai,
      ok: got.akamai === profile.expected.akamai,
    },
  };
  return {
    name,
    ...checked,
    ...(ja3Check ? { ja3: ja3Check } : {}),
    ok: checked.ja4.ok && checked.akamai.ok && (ja3Check?.ok ?? true),
  };
}
