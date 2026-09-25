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
import { verbatim } from './extensions';
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
   * The supported groups to advertise, GREASE included, overriding the TLS
   * library's own list. The key share is still one it can make.
   */
  namedGroups?: readonly number[] | undefined;
  /**
   * What the browser sends with every request, in its order. A handshake that
   * matches Chrome while the headers say "not a browser" fools nobody, and
   * headers are the first thing most checks read.
   *
   * `accept-encoding` is the browser's, brotli and zstd included; a session
   * cuts from it whatever the runtime cannot decode, since offering that is
   * exactly the mistake that broke certificate compression.
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
    /** Only where the order is fixed: a shuffled hello has a new JA3 each time. */
    ja3?: string | undefined;
  };
}

/** A profile that sends what the captured browser sent. */
function fromCapture(capture: Capture): Impersonation {
  return {
    alpn: capture.alpn,
    http2: capture.http2,
    ciphers: capture.ciphers,
    signatureSchemes: capture.signatureSchemes,
    greaseNamedGroup: capture.greaseNamedGroup,
    namedGroups: capture.namedGroups,
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
  edge: targets.edge101,
  firefox: targets.firefox144,
  safari: targets.safari2601,
  safari_ios: targets.safari260_ios,
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
