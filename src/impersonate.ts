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

/** The sixteen reserved values of RFC 8701, which servers must ignore. */
export const GREASE = [
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
  0xcaca, 0xdada, 0xeaea, 0xfafa,
] as const;

export type Extension = readonly [type: number, body: Uint8Array];

export interface Impersonation {
  /** ALPN, in order. `h2` belongs here only once HTTP/2 is real. */
  alpn: readonly string[];
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
  // `h2` is what Chrome sends. Until HTTP/2 exists here, offering it would
  // fail the first handshake a server accepted it on.
  alpn: ['http/1.1'],
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
    [0x001b, bytes(0x02, 0x00, 0x02)], // compress_certificate: brotli
    [0x44cd, alps('h2')], // application_settings
    [0xfe0d, greaseEch(176)], // encrypted_client_hello
    [GREASE[1], bytes(0x00)],
  ],
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
  alpn: ['http/1.1'],
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
    [0x001b, bytes(0x03, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03)], // zlib, brotli, zstd
    [0xfe0d, greaseEch(223)], // encrypted_client_hello
  ],
};

/**
 * Safari 26.3. Like Chrome it GREASEs, but it keeps a fixed extension order,
 * and its signature algorithms really do list PSS-SHA384 twice.
 */
export const safari: Impersonation = {
  alpn: ['http/1.1'],
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
    [0x001b, bytes(0x02, 0x00, 0x01)], // compress_certificate: zlib
    [GREASE[1], bytes(0x00)],
  ],
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
