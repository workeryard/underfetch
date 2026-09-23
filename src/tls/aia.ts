/**
 * Completing a certificate chain the server left short, as browsers do.
 *
 * A server should send its leaf and every intermediate up to a root. Some send
 * the leaf alone; the page still loads in a browser, because the browser reads
 * the address the leaf gives for its issuer (the "CA Issuers" entry of its
 * Authority Information Access extension), fetches that certificate, and
 * builds the path itself. Every other client fails with an unknown issuer.
 *
 * What is fetched here only widens the pool a path may be built from: the TLS
 * module still verifies the whole chain against its own roots, so a fetched
 * certificate can complete a good chain and never excuse a bad one.
 */

/** id-ad-caIssuers, 1.3.6.1.5.5.7.48.2, as it appears in DER. */
const CA_ISSUERS = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
/** A GeneralName's uniformResourceIdentifier: context tag 6, primitive. */
const URI_TAG = 0x86;
/** pkcs7-signedData, 1.2.840.113549.1.7.2, which opens a PKCS#7 bundle. */
const SIGNED_DATA = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/** How far up a chain to chase; real chains are one or two hops short. */
export const MAX_HOPS = 3;
/** Larger than any certificate, small enough that no answer can hurt. */
export const MAX_CERTIFICATE_BYTES = 64 * 1024;

function indexOf(haystack: Uint8Array, needle: readonly number[], from = 0): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * The http(s) address a certificate names for its issuer, if it names one.
 * The OID is unique enough to find by its bytes, which saves writing an X.509
 * parser for one field.
 */
export function caIssuersUrl(der: Uint8Array): string | undefined {
  for (let at = indexOf(der, CA_ISSUERS); at >= 0; at = indexOf(der, CA_ISSUERS, at + 1)) {
    const tag = at + CA_ISSUERS.length;
    if (der[tag] !== URI_TAG) continue;
    let length = der[tag + 1] ?? 0;
    let start = tag + 2;
    if (length === 0x81) {
      length = der[tag + 2] ?? 0;
      start = tag + 3;
    }
    const url = new TextDecoder().decode(der.subarray(start, start + length));
    if (/^https?:\/\//i.test(url)) return url;
  }
  return undefined;
}

/**
 * The certificates in a CA's answer. Most serve one certificate as DER, some
 * as PEM; PKCS#7 bundles are not read, and yield nothing.
 */
export function certificatesIn(body: Uint8Array): Uint8Array[] {
  if (body[0] === 0x30) {
    // A bundle is DER too, and handing it over as a certificate would turn a
    // missing issuer into a malformed one.
    const bundle = indexOf(body.subarray(0, 24), SIGNED_DATA) >= 0;
    return bundle ? [] : [body];
  }
  const text = new TextDecoder().decode(body);
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return (blocks ?? []).map((block) =>
    Uint8Array.from(atob(block.replace(/-----(BEGIN|END) CERTIFICATE-----|\s/g, '')), (c) =>
      c.charCodeAt(0),
    ),
  );
}

/** Certificates as `(length u32, DER)` records, the shape the TLS module reads. */
export function encodeCertificates(certificates: readonly Uint8Array[]): Uint8Array {
  const out = new Uint8Array(certificates.reduce((n, cert) => n + 4 + cert.length, 0));
  const view = new DataView(out.buffer);
  let at = 0;
  for (const cert of certificates) {
    view.setUint32(at, cert.length);
    out.set(cert, at + 4);
    at += 4 + cert.length;
  }
  return out;
}

/** The inverse of `encodeCertificates`. */
export function decodeCertificates(blob: Uint8Array): Uint8Array[] {
  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const out: Uint8Array[] = [];
  for (let at = 0; at + 4 <= blob.length;) {
    const length = view.getUint32(at);
    if (at + 4 + length > blob.length) break;
    out.push(blob.subarray(at + 4, at + 4 + length));
    at += 4 + length;
  }
  return out;
}

/**
 * Walks up from the last certificate the server sent, fetching each issuer in
 * turn, and returns what it found. It stops at a certificate that names no
 * issuer, at an address already visited, or after `MAX_HOPS`.
 */
export async function chaseIssuers(
  presented: readonly Uint8Array[],
  fetchCertificate: (url: string) => Promise<Uint8Array>,
): Promise<Uint8Array[]> {
  const found: Uint8Array[] = [];
  const seen = new Set<string>();
  let current = presented.at(-1);
  for (let hop = 0; hop < MAX_HOPS && current !== undefined; hop++) {
    const url = caIssuersUrl(current);
    if (url === undefined || seen.has(url)) break;
    seen.add(url);
    const certificates = certificatesIn(await fetchCertificate(url));
    if (certificates.length === 0) break;
    found.push(...certificates);
    current = certificates[0];
  }
  return found;
}
