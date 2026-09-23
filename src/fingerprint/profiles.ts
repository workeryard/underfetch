/**
 * What a ClientHello should look like on the wire.
 *
 * A stock rustls handshake is recognisable at a glance, so the TLS module
 * takes its cipher list, its signature algorithms and its extra extensions
 * from here. That makes a browser a table of numbers rather than a change to
 * any Rust: to add one, copy its ClientHello and write it down.
 *
 * The browsers themselves are data, in `browsers.ts`, imported from
 * curl-impersonate's captures of real browsers; this turns one into what the
 * TLS module and the HTTP/2 client take.
 */

import { captures } from './browsers';
import type { Capture } from './capture';
import { GREASE } from './grease';
import type { Http2Profile } from '../http/h2/connection';

export { GREASE };

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
   * What the browser sends with every request, in its order. A handshake that
   * matches Chrome while the headers say "not a browser" fools nobody, and
   * headers are the first thing most checks read.
   *
   * `accept-encoding` is deliberately ours rather than the browser's: a real
   * one offers brotli and zstd, and offering what we cannot decode is exactly
   * the mistake that broke certificate compression.
   */
  headers: readonly (readonly [string, string])[];
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
 * The extensions a capture names that the TLS library does not build itself,
 * with the body each carries. Everything else in a capture's list — groups,
 * key shares, versions, ALPN — rustls writes, from the fields it was given.
 */
function verbatim(capture: Capture, type: number): Uint8Array | undefined {
  switch (type) {
    case GREASE[0]:
      return bytes();
    case GREASE[1]:
      return bytes(0x00);
    case 0xff01: // renegotiation_info
      return bytes(0x00);
    case 0x0012: // signed_certificate_timestamp
      return bytes();
    case 0x4469: // application_settings, before Chrome 133
    case 0x44cd: // application_settings
      return alps(...(capture.alps ?? ['h2']));
    case 0xfe0d: // encrypted_client_hello
      return greaseEch(capture.echPayload ?? 176);
    case 0x0022: // delegated_credentials
      return schemeList(...(capture.delegatedCredentials ?? []));
    case 0x001c: {
      // record_size_limit
      const limit = capture.recordSizeLimit ?? 16385;
      return bytes(limit >> 8, limit & 0xff);
    }
    default:
      return undefined;
  }
}

/** A profile that sends what the captured browser sent. */
function fromCapture(capture: Capture): Impersonation {
  return {
    alpn: capture.alpn,
    http2: capture.http2,
    ciphers: capture.ciphers,
    signatureSchemes: capture.signatureSchemes,
    greaseNamedGroup: capture.greaseNamedGroup,
    // Chrome shuffles; a fixed order would itself give it away.
    extensionOrder: capture.shuffled ? undefined : capture.extensions,
    extensions: () =>
      capture.extensions.flatMap((type): Extension[] => {
        const body = verbatim(capture, type);
        return body === undefined ? [] : [[type, body]];
      }),
    headers: capture.headers,
    expected: capture.expected,
  };
}

/** A list of signature schemes, length-prefixed, as several extensions want. */
function schemeList(...schemes: number[]): Uint8Array {
  const body = new Uint8Array(2 + schemes.length * 2);
  const view = new DataView(body.buffer);
  view.setUint16(0, schemes.length * 2);
  schemes.forEach((scheme, i) => view.setUint16(2 + i * 2, scheme));
  return body;
}

type Target = keyof typeof captures;

const targets = Object.fromEntries(
  Object.entries(captures).map(([name, capture]) => [name, fromCapture(capture)]),
) as Record<Target, Impersonation>;

/**
 * Every browser, by the names impers gives them, plus the short names it
 * points at the newest of each. Firefox's newest is 144 rather than impers'
 * 147: 147 has no capture to take it from.
 */
export const profiles = {
  ...targets,
  chrome: targets.chrome150,
  chrome_android: targets.chrome131_android,
  firefox: targets.firefox144,
  safari: targets.safari2601,
  tor: targets.tor145,
} as const;

export const { chrome, firefox, safari } = profiles;

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
