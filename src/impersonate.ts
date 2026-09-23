/**
 * What a ClientHello should look like on the wire.
 *
 * A stock rustls handshake is recognisable at a glance, so the TLS module
 * takes its cipher list, its signature algorithms and its extra extensions
 * from here. That makes a browser a table of numbers rather than a change to
 * any Rust: to add one, copy its ClientHello and write it down.
 *
 * The reference for every profile is utls (`u_parrots.go`), which records what
 * each browser actually sends.
 */

import type { Http2Profile } from './h2/connection';
import { Setting } from './h2/frames';

/** The sixteen reserved values of RFC 8701, which servers must ignore. */
export const GREASE = [
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa,
] as const;

export type Extension = readonly [type: number, body: Uint8Array];

export interface Impersonation {
  /** ALPN, in order. */
  alpn: readonly string[];
  /**
   * The HTTP/2 settings, window update and pseudo-header order. A browser is
   * as recognisable by its SETTINGS frame as by its ClientHello — this is what
   * an Akamai fingerprint reads.
   */
  http2: Http2Profile;
  /** Offered verbatim, GREASE included; half of a browser's list is bluff. */
  ciphers: readonly number[];
  /** Offered verbatim, in this order. */
  signatureSchemes: readonly number[];
  /** Puts a GREASE value at the head of the supported groups. */
  greaseNamedGroup: boolean;
  /**
   * The exact order to write extensions in. Left out, they are shuffled, which
   * is what Chrome does; Firefox and Safari send a fixed order.
   */
  extensionOrder?: readonly number[] | undefined;
  /**
   * Extensions the TLS library does not build itself. Called once per
   * connection, so anything that must differ every time can differ.
   */
  extensions: () => readonly Extension[];
  /**
   * What the real browser's fingerprints are. `verifyProfile` checks what we
   * actually emit against these, so a profile that drifts fails loudly instead
   * of quietly impersonating nobody.
   */
  expected: {
    ja4: string;
    akamai: string;
  };
}

const bytes = (...values: number[]) => new Uint8Array(values);

const random = (length: number): Uint8Array => {
  const buffer = new Uint8Array(length);
  crypto.getRandomValues(buffer);
  return buffer;
};

/**
 * A GREASE ECH extension: shaped like the real thing, carrying noise. Fresh
 * bytes every handshake, because a fixed payload would itself be a
 * fingerprint — the opposite of the point.
 */
function greaseEch(payloadLength: number): Uint8Array {
  const key = random(32); // an X25519 public key
  const payload = random(payloadLength);
  const body = new Uint8Array(1 + 2 + 2 + 1 + 2 + key.length + 2 + payload.length);
  const view = new DataView(body.buffer);
  let at = 0;
  body[at++] = 0x00; // outer
  view.setUint16(at, 0x0001); // HKDF-SHA256
  at += 2;
  view.setUint16(at, 0x0001); // AES-128-GCM
  at += 2;
  body[at++] = random(1)[0]!; // config id
  view.setUint16(at, key.length);
  at += 2;
  body.set(key, at);
  at += key.length;
  view.setUint16(at, payload.length);
  at += 2;
  body.set(payload, at);
  return body;
}

/** ALPS (`application_settings`), naming the protocols it applies to. */
const alps = (...protocols: string[]): Uint8Array => {
  const encoded = protocols.map((name) => new TextEncoder().encode(name));
  const length = encoded.reduce((total, name) => total + 1 + name.length, 0);
  const body = new Uint8Array(2 + length);
  new DataView(body.buffer).setUint16(0, length);
  let at = 2;
  for (const name of encoded) {
    body[at++] = name.length;
    body.set(name, at);
    at += name.length;
  }
  return body;
};

/**
 * Chrome 133. Verified: its JA4 cipher and extension hashes come out as
 * `8daaf6152771` and `d8a2da3f94cd`, which `test/fingerprint.test.ts` pins.
 */
export const chrome: Impersonation = {
  alpn: ['h2', 'http/1.1'],
  // Akamai: 1:65536,2:0,4:6291456,6:262144|15663105|0|m,a,s,p
  http2: {
    settings: [
      [Setting.HeaderTableSize, 65536],
      [Setting.EnablePush, 0],
      [Setting.InitialWindowSize, 6291456],
      [Setting.MaxHeaderListSize, 262144],
    ],
    windowUpdate: 15663105,
    pseudoHeaderOrder: ['m', 'a', 's', 'p'],
  },
  ciphers: [
    GREASE[0],
    0x1301,
    0x1302,
    0x1303,
    0xc02b,
    0xc02f,
    0xc02c,
    0xc030,
    0xcca9,
    0xcca8,
    0xc013,
    0xc014,
    0x009c,
    0x009d,
    0x002f,
    0x0035,
  ],
  signatureSchemes: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
  greaseNamedGroup: true,
  extensions: () => [
    [GREASE[0], bytes()],
    [0xff01, bytes(0x00)], // renegotiation_info
    [0x0012, bytes()], // signed_certificate_timestamp
    [0x44cd, alps('h2')], // application_settings
    [0xfe0d, greaseEch(176)], // encrypted_client_hello
    [GREASE[1], bytes(0x00)],
  ],
  expected: {
    ja4: 't13d1516h2_8daaf6152771_d8a2da3f94cd',
    akamai: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
  },
};

/** A list of signature schemes, length-prefixed, as several extensions want. */
const schemeList = (...schemes: number[]): Uint8Array => {
  const body = new Uint8Array(2 + schemes.length * 2);
  const view = new DataView(body.buffer);
  view.setUint16(0, schemes.length * 2);
  schemes.forEach((scheme, i) => view.setUint16(2 + i * 2, scheme));
  return body;
};

/**
 * Firefox 148. Two things separate it from Chrome and both are structural: it
 * sends no GREASE anywhere, and its extensions come in a fixed order rather
 * than shuffled.
 */
export const firefox: Impersonation = {
  alpn: ['h2', 'http/1.1'],
  // Akamai: 1:65536,2:0,4:131072,5:16384|12517377|...|m,p,a,s
  // The priority frames Firefox also sends are not reproduced.
  http2: {
    settings: [
      [Setting.HeaderTableSize, 65536],
      [Setting.EnablePush, 0],
      [Setting.InitialWindowSize, 131072],
      [Setting.MaxFrameSize, 16384],
    ],
    windowUpdate: 12517377,
    pseudoHeaderOrder: ['m', 'p', 'a', 's'],
  },
  ciphers: [
    0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
  ],
  signatureSchemes: [
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
  ],
  greaseNamedGroup: false,
  extensionOrder: [
    0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033, 0x002b, 0x000d,
    0x001c, 0x001b, 0xfe0d,
  ],
  extensions: () => [
    [0xff01, bytes(0x00)], // renegotiation_info
    [0x0022, schemeList(0x0403, 0x0503, 0x0603, 0x0203)], // delegated_credentials
    [0x0012, bytes()], // signed_certificate_timestamp
    [0x001c, bytes(0x40, 0x01)], // record_size_limit
    [0xfe0d, greaseEch(223)], // encrypted_client_hello
  ],
  expected: {
    ja4: 't13d1715h2_5b57614c22b0_a54fffd0eb61',
    akamai: '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
  },
};

/**
 * Safari 26.3. Like Chrome it GREASEs, but it keeps a fixed extension order,
 * and its signature algorithms really do list PSS-SHA384 twice.
 */
export const safari: Impersonation = {
  alpn: ['h2', 'http/1.1'],
  // Akamai: 2:0,3:100,4:2097152,8:1,9:1|10485760|0|m,s,p,a
  http2: {
    settings: [
      [Setting.EnablePush, 0],
      [Setting.MaxConcurrentStreams, 100],
      [Setting.InitialWindowSize, 2097152],
      [0x8, 1],
      [0x9, 1],
    ],
    windowUpdate: 10485760,
    pseudoHeaderOrder: ['m', 's', 'p', 'a'],
  },
  ciphers: [
    GREASE[0],
    0x1302,
    0x1303,
    0x1301,
    0xc02c,
    0xc02b,
    0xcca9,
    0xc030,
    0xc02f,
    0xcca8,
    0xc00a,
    0xc009,
    0xc014,
    0xc013,
    0x009d,
    0x009c,
    0x0035,
    0x002f,
    0xc008,
    0xc012,
    0x000a,
  ],
  signatureSchemes: [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
  ],
  greaseNamedGroup: true,
  extensionOrder: [
    GREASE[0],
    0x0000,
    0x0017,
    0xff01,
    0x000a,
    0x000b,
    0x0010,
    0x0005,
    0x000d,
    0x0012,
    0x0033,
    0x002d,
    0x002b,
    0x001b,
    GREASE[1],
  ],
  extensions: () => [
    [GREASE[0], bytes()],
    [0xff01, bytes(0x00)], // renegotiation_info
    [0x0012, bytes()], // signed_certificate_timestamp
    [GREASE[1], bytes(0x00)],
  ],
  expected: {
    ja4: 't13d2013h2_a09f3c656075_7f0f34a4126d',
    akamai: '2:0;3:100;4:2097152;8:1;9:1|10485760|0|m,s,p,a',
  },
};

export const profiles = { chrome, firefox, safari } as const;

export type ProfileName = keyof typeof profiles;

/** Flattens extensions into the `(type, length, body)` triples the TLS side reads. */
export function encodeExtensions(extensions: readonly Extension[]): Uint8Array {
  const size = extensions.reduce((total, [, body]) => total + 4 + body.length, 0);
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  let at = 0;
  for (const [type, body] of extensions) {
    view.setUint16(at, type);
    view.setUint16(at + 2, body.length);
    out.set(body, at + 4);
    at += 4 + body.length;
  }
  return out;
}
