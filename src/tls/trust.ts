/**
 * Whom a session's TLS trusts, and who it says it is.
 *
 * By default a server's certificate must chain to the web PKI's roots, as in
 * a browser. A service on a private CA needs that CA instead; one under test
 * may need no checking at all; and one that asks who is calling needs a
 * client certificate. All three belong to the session, not to a request:
 * rustls resumes a ticket only under the verifier and certificate that earned
 * it, so they are fixed when its ticket store is made.
 */

import { encodeCertificates } from './aia';

/** One certificate or several: PEM text, or DER bytes. */
export type Certificates = string | Uint8Array | readonly (string | Uint8Array)[];

export interface TrustOptions {
  /**
   * Check the server's certificate. Default: true. `false` takes any
   * certificate for any name, as `curl -k` does — the handshake must still
   * be signed by the key of the certificate presented, but anyone between
   * you and the server can present one. For a service under test only.
   */
  verify?: boolean | undefined;
  /**
   * The CAs to trust, **instead of** the web PKI's roots, as curl's
   * `--cacert` and Node's `ca` replace theirs. Give the web's too, and a
   * public site, by passing them along.
   */
  ca?: Certificates | undefined;
  /**
   * What to present when a server asks for a certificate — mutual TLS. The
   * chain is the client's certificate first, then any intermediates; the
   * key is PEM, or DER as PKCS#8, PKCS#1 or SEC1. RSA, ECDSA on P-256 or
   * P-384, and Ed25519 keys can sign.
   */
  clientCert?: { cert: Certificates; key: string | Uint8Array } | undefined;
}

const bytes = (item: string | Uint8Array) =>
  typeof item === 'string' ? new TextEncoder().encode(item) : item;

/** The `(length u32, DER or PEM)` records the TLS module reads. */
export function encodeGiven(certificates: Certificates): Uint8Array {
  const list =
    typeof certificates === 'string' || certificates instanceof Uint8Array
      ? [certificates]
      : certificates;
  return encodeCertificates(list.map(bytes));
}

/** The store's arguments: CA, verify, client chain, client key. */
export function trustArguments(trust: TrustOptions = {}) {
  return [
    trust.ca === undefined ? undefined : encodeGiven(trust.ca),
    trust.verify,
    trust.clientCert === undefined ? undefined : encodeGiven(trust.clientCert.cert),
    trust.clientCert === undefined ? undefined : bytes(trust.clientCert.key),
  ] as const;
}

/** Whether `trust` asks for anything beyond the default. */
export const customTrust = (trust: TrustOptions = {}) =>
  trust.verify === false || trust.ca !== undefined || trust.clientCert !== undefined;
