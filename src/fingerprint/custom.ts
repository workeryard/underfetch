/**
 * A profile from the two strings a fingerprinting page shows.
 *
 * Open tls.peet.ws/api/all in the browser to copy, take its `ja3` and its
 * `akamai_fingerprint`, and this turns them into a profile — no table of
 * numbers to write. JA3 carries the ciphers, the extensions in order, the
 * groups and the point formats; the Akamai string carries the HTTP/2 SETTINGS,
 * window update and pseudo-header order. What neither carries — signature
 * algorithms, headers, ALPN, and the bodies of extensions such as ALPS and ECH
 * — comes from a base profile, which should be the same browser family.
 *
 * Anything the strings ask for that cannot be sent is refused with the reason,
 * never quietly dropped: a profile that is almost right is a fingerprint of
 * its own.
 */

import type { Http2Profile } from '../http/h2/connection';
import { BUILT_BY_TLS, verbatim } from './extensions';
import { GREASE } from './grease';
import type { Extension, Impersonation } from './profiles';
import { akamai as akamaiOf, ja3 as ja3Of } from './verify';

export class FingerprintError extends Error {
  override name = 'FingerprintError';
}

/**
 * Kyber's draft hybrid, which Chrome 124 to 130 offered: nothing here can
 * make it, and offered without a key share it makes servers ask again.
 */
const UNMAKEABLE = [0x6399];
/** Extensions only a resumed session sends. */
const RESUMPTION_ONLY = [0x0029];
/** Bodies we can write when the base profile has none to lend. */
const KNOWN_BODIES = [0xff01, 0x0012, 0x0015, 0x001c, 0x0022, 0x4469, 0x44cd, 0xfe0d];
/** What those bodies hold when the base lends none: the values browsers send. */
const DEFAULT_DETAILS = {
  alps: ['h2'],
  echPayload: 176,
  // Only Firefox sends delegated_credentials, and always this list.
  delegatedCredentials: [0x0403, 0x0503, 0x0603, 0x0203],
  recordSizeLimit: 0x4001,
};

const numbers = (field: string | undefined) => (field ?? '').split('-').filter(Boolean).map(Number);

export interface Fingerprints {
  /** A JA3 string, GREASE left out, as tls.peet.ws prints it. */
  ja3?: string | undefined;
  /** An Akamai HTTP/2 string, e.g. `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`. */
  akamai?: string | undefined;
  /**
   * JA3 records one order, but Chrome shuffles on every connection. `true`
   * shuffles too; JA4 then still matches and JA3 changes every time, as
   * Chrome's does. Default: false, the order given.
   */
  shuffle?: boolean | undefined;
}

function parseAkamai(akamai: string, base: Http2Profile): Http2Profile {
  const [settings, window, priority, pseudo] = akamai.split('|');
  if (pseudo === undefined) throw new FingerprintError(`not an Akamai string: ${akamai}`);
  if (priority !== '0' && priority !== '') {
    throw new FingerprintError(
      `the Akamai string names PRIORITY frames (${priority}), which are not sent`,
    );
  }
  const order = pseudo.split(',').filter(Boolean);
  if (order.some((p) => !['m', 'a', 's', 'p'].includes(p))) {
    throw new FingerprintError(`unknown pseudo-header order: ${pseudo}`);
  }
  return {
    settings: (settings ?? '')
      .split(/[;,]/)
      .filter(Boolean)
      .map((pair) => {
        const [id, value] = pair.split(':').map(Number);
        if (!Number.isInteger(id) || !Number.isInteger(value)) {
          throw new FingerprintError(`bad setting in the Akamai string: ${pair}`);
        }
        return [id!, value!] as const;
      }),
    windowUpdate: Number(window) || 0,
    pseudoHeaderOrder: order as Http2Profile['pseudoHeaderOrder'],
    priority: base.priority,
  };
}

/**
 * `base`, sending the given JA3 and Akamai strings instead of its own. Either
 * may be left out, and what neither says — signature algorithms, headers,
 * extension bodies — comes from `base`.
 *
 * With a JA3, the profile is judged by it: `expected.ja3` is the string that
 * will go out, and no JA4 is claimed, since one computed here would only
 * restate the input. With an Akamai string alone, the TLS side is still
 * `base`'s and so is its JA4.
 */
export function withFingerprints(
  base: Impersonation,
  { ja3, akamai, shuffle = false }: Fingerprints,
): Impersonation {
  const http2 = akamai === undefined ? base.http2 : parseAkamai(akamai, base.http2);
  if (ja3 === undefined) {
    return { ...base, http2, expected: { ...base.expected, akamai: akamaiOf(http2) } };
  }

  const [version, cipherField, extensionField, groupField, formatField] = ja3.split(',');
  if (formatField === undefined) throw new FingerprintError(`not a JA3 string: ${ja3}`);
  if (version !== '771') {
    throw new FingerprintError(`JA3 version ${version} is not TLS 1.2/1.3 (771)`);
  }

  const extensions = numbers(extensionField).filter((e) => !RESUMPTION_ONLY.includes(e));
  const lent = new Map(base.extensions().map(([type, body]) => [type, body] as const));
  const unsendable = extensions.filter(
    (e) => !BUILT_BY_TLS.includes(e) && !KNOWN_BODIES.includes(e) && !lent.has(e),
  );
  if (unsendable.length > 0) {
    throw new FingerprintError(`the TLS module cannot send extension ${unsendable.join(', ')}`);
  }
  if (extensions.includes(0x000b) && formatField !== '0') {
    throw new FingerprintError(`only uncompressed points can be offered, not ${formatField}`);
  }

  const groups = numbers(groupField).filter((g) => !UNMAKEABLE.includes(g));
  if (!groups.includes(0x001d)) {
    throw new FingerprintError('the groups must include X25519, the one key share sent');
  }

  // GREASE is left out of JA3, so where it goes is the base browser's habit.
  const baseGreases = base.ciphers[0] === GREASE[0];
  const lentTypes = [...lent.keys()];
  const leadGrease = lentTypes.includes(GREASE[0]) ? [GREASE[0]] : [];
  const trailGrease = lentTypes.includes(GREASE[1]) ? [GREASE[1]] : [];
  const order = [...leadGrease, ...extensions, ...trailGrease];
  const ciphers = [...(baseGreases ? [GREASE[0]] : []), ...numbers(cipherField)];
  const namedGroups = [...(base.greaseNamedGroup ? [GREASE[0]] : []), ...groups];

  const profile: Impersonation = {
    ...base,
    ciphers,
    namedGroups,
    http2,
    extensionOrder: shuffle ? undefined : order,
    extensions: () => {
      // Bodies are drawn afresh each connection: ECH's must be new noise.
      const fresh = new Map(base.extensions().map(([type, body]) => [type, body] as const));
      return order.flatMap((type): Extension[] => {
        const body = fresh.get(type) ?? verbatim(DEFAULT_DETAILS, type);
        return body === undefined ? [] : [[type, body]];
      });
    },
    expected: {
      akamai: akamaiOf(http2),
      // What will actually go out: the given string, less what cannot.
      ...(shuffle
        ? {}
        : {
            ja3: ja3Of({
              ciphers,
              extensions: order,
              signatureSchemes: [],
              alpn: [],
              hasServerName: false,
              groups: namedGroups,
              pointFormats: extensions.includes(0x000b) ? [0] : [],
            }),
          }),
    },
  };
  return profile;
}
