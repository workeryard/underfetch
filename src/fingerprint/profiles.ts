/**
 * What a ClientHello should look like on the wire.
 *
 * A stock rustls handshake is recognisable at a glance, so the TLS module
 * takes its cipher list, its signature algorithms and its extra extensions
 * from here. That makes a browser a table of numbers rather than a change to
 * any Rust: to add one, copy its ClientHello and write it down.
 *
 * The browsers themselves are data, in `browsers/`, imported from
 * curl-impersonate's captures of real browsers; this turns one into what the
 * TLS module and the HTTP/2 client take.
 */

import { familyOf, type Family } from './order';
import { captures } from './browsers/index';
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
   * The groups to send a key share for, as the browser does — X25519MLKEM768
   * and X25519, and P-256 too for Firefox. Only groups named above count, and
   * only these three can be made; left out, a share for the first group the
   * TLS library leads with.
   */
  keyShares?: readonly number[] | undefined;
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
   * Which browser engine this is, for what the captures do not hold: the
   * header order of requests other than a page load, and what a script's
   * fetch() sends. Left out, a profile's headers keep their own order and
   * only page loads are imitated. See `order.ts`.
   */
  family?: Family | undefined;
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
    /**
     * Left out for a profile built from a JA3 string, which is judged by that
     * string instead: a JA4 computed from it would only restate it.
     */
    ja4?: string | undefined;
    akamai: string;
    /** Only where the order is fixed: a shuffled hello has a new JA3 each time. */
    ja3?: string | undefined;
  };
}

/**
 * How a browser numbers, chains and widens its HTTP/2 streams, which no
 * capture records — the Akamai string is the connection's opening alone.
 * Measured on 2026-10-18 with Chrome 155, Edge 154 and Firefox 158 on
 * Windows, behind a proxy that logged every frame they sent
 * (`scripts/capture-frames.ts`): four images at once, four fetch() calls at
 * once, then two one after the other.
 *
 * Chromium chains streams open at once, each depending exclusively on the
 * last; one sent after the others finished depends on none. Firefox starts
 * at stream 3, depends on none, and widens each stream's 128 KB window to
 * 12 MB with a WINDOW_UPDATE straight after its HEADERS. The Firefox values
 * were measured on 158; the older profiles open with the same SETTINGS and
 * no PRIORITY frames, which is what starting at 3 goes with, but were not
 * themselves watched. There is no Safari measurement.
 */
const STREAMS: Partial<Record<Family, Partial<Http2Profile>>> = {
  chromium: { dependOnOpen: true },
  firefox: { firstStream: 3, streamWindowUpdate: 12_451_840 },
};

/** A profile that sends what the captured browser sent. */
function fromCapture(capture: Capture): Impersonation {
  const family = familyOf(capture.source);
  return {
    alpn: capture.alpn,
    http2: { ...capture.http2, ...(family === undefined ? {} : STREAMS[family]) },
    ciphers: capture.ciphers,
    signatureSchemes: capture.signatureSchemes,
    greaseNamedGroup: capture.greaseNamedGroup,
    namedGroups: capture.namedGroups,
    keyShares: capture.keyShares,
    // Chrome shuffles; a fixed order would itself give it away.
    extensionOrder: capture.shuffled ? undefined : capture.extensions,
    extensions: () =>
      capture.extensions.flatMap((type): Extension[] => {
        const body = verbatim(capture, type);
        return body === undefined ? [] : [[type, body]];
      }),
    headers: capture.headers,
    family,
    expected: capture.expected,
  };
}

type Target = keyof typeof captures;

const targets = Object.fromEntries(
  Object.entries(captures).map(([name, capture]) => [name, fromCapture(capture)]),
) as Record<Target, Impersonation>;

/**
 * Every browser, by the names impers gives them, plus the short names it
 * points at the newest of each. Firefox's newest is 158, recorded here
 * (captures/), past impers' 147, of which no capture was published.
 */
export const profiles = {
  ...targets,
  chrome: targets.chrome150,
  chrome_android: targets.chrome131_android,
  edge: targets.edge101,
  firefox: targets.firefox158,
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
