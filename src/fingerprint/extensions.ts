/**
 * The bodies of the extensions a browser sends that the TLS library does not
 * build itself. Everything else in a ClientHello — groups, key shares,
 * versions, ALPN — rustls writes, from the fields it was given.
 */

import { GREASE } from './grease';

/** What some of these bodies are made from; a capture carries all of it. */
export interface VerbatimDetails {
  alps?: readonly string[] | undefined;
  echPayload?: number | undefined;
  delegatedCredentials?: readonly number[] | undefined;
  recordSizeLimit?: number | undefined;
}

/** Extensions rustls builds, and so needs no body from us. */
export const BUILT_BY_TLS: readonly number[] = [
  0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033,
];

export const bytes = (...values: number[]) => new Uint8Array(values);

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
export function greaseEch(payloadLength: number): Uint8Array {
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
export const alps = (...protocols: string[]): Uint8Array => {
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
 * The body of an extension the TLS library does not build,
 * with the body each carries. Everything else in a capture's list — groups,
 * key shares, versions, ALPN — rustls writes, from the fields it was given.
 */
export function verbatim(details: VerbatimDetails, type: number): Uint8Array | undefined {
  switch (type) {
    case GREASE[0]:
      return bytes();
    case GREASE[1]:
      return bytes(0x00);
    case 0xff01: // renegotiation_info
      return bytes(0x00);
    case 0x0012: // signed_certificate_timestamp
      return bytes();
    case 0x0015: // padding: a request for it; the TLS module sizes it
      return bytes();
    case 0x4469: // application_settings, before Chrome 133
    case 0x44cd: // application_settings
      return alps(...(details.alps ?? ['h2']));
    case 0xfe0d: // encrypted_client_hello
      return greaseEch(details.echPayload ?? 176);
    case 0x0022: // delegated_credentials
      return schemeList(...(details.delegatedCredentials ?? []));
    case 0x001c: {
      // record_size_limit
      const limit = details.recordSizeLimit ?? 16385;
      return bytes(limit >> 8, limit & 0xff);
    }
    default:
      return undefined;
  }
}

/** A list of signature schemes, length-prefixed, as several extensions want. */
export function schemeList(...schemes: number[]): Uint8Array {
  const body = new Uint8Array(2 + schemes.length * 2);
  const view = new DataView(body.buffer);
  view.setUint16(0, schemes.length * 2);
  schemes.forEach((scheme, i) => view.setUint16(2 + i * 2, scheme));
  return body;
}
