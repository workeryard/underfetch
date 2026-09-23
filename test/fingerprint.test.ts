import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { chrome, encodeExtensions, firefox, type Impersonation } from '../src/impersonate';
import { initSync, TlsClient } from '../rust-tls/pkg/underfetch_tls';

/**
 * The fingerprint is a feature, so it gets a test rather than a measurement
 * someone took once. Nothing here touches the network: a ClientHello is a
 * deterministic function of the configuration, so it can be read straight out
 * of the session and taken apart.
 *
 * The values are Chrome 133's, as recorded by utls in `u_parrots.go`.
 */

const wasm = new WebAssembly.Module(
  readFileSync(fileURLToPath(new URL('../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url))),
);

/** True for the sixteen reserved values of RFC 8701, which are all 0x?A?A. */
const isGrease = (value: number) => (value & 0x0f0f) === 0x0a0a && value >> 8 === (value & 0xff);

interface Hello {
  ciphers: number[];
  extensions: number[];
  signatureSchemes: number[];
}

/** Reads the parts of a ClientHello record that a fingerprint is built from. */
function parse(record: Uint8Array): Hello {
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
  while (at < end) {
    const type = view.getUint16(at);
    const length = view.getUint16(at + 2);
    extensions.push(type);
    if (type === 0x000d) {
      const listBytes = view.getUint16(at + 4);
      signatureSchemes = [];
      for (let i = 0; i < listBytes; i += 2) signatureSchemes.push(view.getUint16(at + 6 + i));
    }
    at += 4 + length;
  }
  return { ciphers, extensions, signatureSchemes };
}

const hex = (value: number) => value.toString(16).padStart(4, '0');
const truncatedSha256 = (text: string) =>
  createHash('sha256').update(text).digest('hex').slice(0, 12);

function helloFor(as: Impersonation, alpn = 'http/1.1'): Hello {
  initSync({ module: wasm });
  const session = new TlsClient(
    'example.com',
    alpn,
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
    as.greaseNamedGroup,
    as.extensionOrder === undefined ? undefined : new Uint16Array(as.extensionOrder),
  );
  return parse(session.outgoing());
}

const hello = (alpn = 'http/1.1') => helloFor(chrome, alpn);

/** JA4's two hashes, from a ClientHello rather than from a claim. */
function ja4(seen: Hello): { ciphers: string; extensions: string; counts: string } {
  const suites = seen.ciphers.filter((c) => !isGrease(c)).map(hex);
  const listed = seen.extensions
    .filter((e) => !isGrease(e) && e !== 0x0000 && e !== 0x0010)
    .map(hex)
    .sort();
  const all = seen.extensions.filter((e) => !isGrease(e)).length;
  return {
    ciphers: truncatedSha256([...suites].sort().join(',')),
    extensions: truncatedSha256(`${listed.join(',')}_${seen.signatureSchemes.map(hex).join(',')}`),
    counts: `${suites.length}${all}`,
  };
}

/** The same session with no profile at all, which is rustls being itself. */
function plainHello(): Hello {
  initSync({ module: wasm });
  return parse(new TlsClient('example.com', 'http/1.1').outgoing());
}

describe('the ClientHello', () => {
  it('carries GREASE where a browser carries it', () => {
    const { ciphers, extensions } = hello();
    expect(isGrease(ciphers[0]!)).toBe(true);
    // Two GREASE extensions, as a browser brackets its list with.
    expect(extensions.filter(isGrease)).toHaveLength(2);
    expect(isGrease(extensions[0]!)).toBe(true);
  });

  it('offers exactly the cipher suites Chrome offers, in order', () => {
    const { ciphers } = hello();
    expect(ciphers.filter((c) => !isGrease(c)).map(hex)).toEqual([
      '1301',
      '1302',
      '1303',
      'c02b',
      'c02f',
      'c02c',
      'c030',
      'cca9',
      'cca8',
      'c013',
      'c014',
      '009c',
      '009d',
      '002f',
      '0035',
    ]);
  });

  it('sends the extensions Chrome sends, and no others', () => {
    const { extensions } = hello();
    expect(
      extensions
        .filter((e) => !isGrease(e))
        .map(hex)
        .sort(),
    ).toEqual([
      '0000', // server_name
      '0005', // status_request
      '000a', // supported_groups
      '000b', // ec_point_formats
      '000d', // signature_algorithms
      '0010', // alpn
      '0012', // signed_certificate_timestamp
      '0017', // extended_master_secret
      '001b', // compress_certificate
      '0023', // session_ticket
      '002b', // supported_versions
      '002d', // psk_key_exchange_modes
      '0033', // key_share
      '44cd', // application_settings
      'fe0d', // encrypted_client_hello
      'ff01', // renegotiation_info
    ]);
  });

  it('matches Chrome 133 in both halves of its JA4', () => {
    const { ciphers, extensions, signatureSchemes } = hello();

    const suites = ciphers.filter((c) => !isGrease(c)).map(hex);
    expect(truncatedSha256([...suites].sort().join(','))).toBe('8daaf6152771');

    // JA4 leaves server_name and ALPN out of the extension hash, and takes the
    // signature algorithms in the order they were sent.
    const listed = extensions
      .filter((e) => !isGrease(e) && e !== 0x0000 && e !== 0x0010)
      .map(hex)
      .sort();
    const digest = truncatedSha256(`${listed.join(',')}_${signatureSchemes.map(hex).join(',')}`);
    expect(digest).toBe('d8a2da3f94cd');
  });

  it("is Firefox 148 when asked for Firefox, in Firefox's fixed order", () => {
    const seen = helloFor(firefox);
    const fingerprint = ja4(seen);

    expect(fingerprint.counts).toBe('1715');
    expect(fingerprint.ciphers).toBe('5b57614c22b0');
    expect(fingerprint.extensions).toBe('a54fffd0eb61');
    // Firefox GREASEs nothing at all, unlike Chrome.
    expect(seen.ciphers.filter(isGrease)).toHaveLength(0);
    expect(seen.extensions.filter(isGrease)).toHaveLength(0);
    // And it sends them in the order it was given, not shuffled.
    expect(seen.extensions.map(hex)).toEqual((firefox.extensionOrder ?? []).map(hex));
  });

  it('sends no GREASE at all when no profile was asked for', () => {
    const { ciphers, extensions } = plainHello();
    expect(ciphers.filter(isGrease)).toHaveLength(0);
    expect(extensions.filter(isGrease)).toHaveLength(0);
    // And none of the extensions a browser sends but rustls does not build.
    expect(extensions).not.toContain(0x44cd);
    expect(extensions).not.toContain(0xfe0d);
  });

  it('draws fresh ECH noise for every connection', () => {
    const first = hello().extensions;
    const second = hello().extensions;
    // The types are stable even though the bytes underneath are not.
    expect(first.filter(isGrease)).toEqual(second.filter(isGrease));
    expect(encodeExtensions(chrome.extensions())).not.toEqual(
      encodeExtensions(chrome.extensions()),
    );
  });

  it('still says http/1.1, because that is all it can speak', () => {
    // Chrome's JA4 ends `h2`. Offering it before HTTP/2 exists would fail the
    // first handshake a server accepted it on, so this stays until then.
    const { extensions } = hello();
    expect(extensions).toContain(0x0010);
  });
});
