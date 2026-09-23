import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { encodeExtensions, profiles, type Impersonation } from '../src/impersonate';
import { akamai, ja4, parseClientHello, verifyProfile, VerifyError } from '../src/verify';
import { initSync, TlsClient } from '../rust-tls/pkg/underfetch_tls';

/**
 * The library checks its own fingerprints rather than sending a handshake to
 * someone else's website and believing the answer. Both are computed from
 * bytes generated here, so this runs with no network at all.
 */

const wasm = new WebAssembly.Module(
  readFileSync(fileURLToPath(new URL('../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url))),
);

function clientHello(as: Impersonation): Uint8Array {
  initSync({ module: wasm });
  const session = new TlsClient(
    'example.com',
    as.alpn.join(','),
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
    as.greaseNamedGroup,
    as.extensionOrder === undefined ? undefined : new Uint16Array(as.extensionOrder),
  );
  return session.outgoing();
}

describe('self-verification', () => {
  it.each(Object.entries(profiles))('%s matches the browser it claims', async (name, profile) => {
    const verdict = await verifyProfile(name, profile, clientHello(profile));

    // Reported side by side so a failure says what drifted, not just that it did.
    expect({ ja4: verdict.ja4.got, akamai: verdict.akamai.got }).toEqual({
      ja4: verdict.ja4.want,
      akamai: verdict.akamai.want,
    });
    expect(verdict.ok).toBe(true);
  });

  it('reads the ALPN back out of the handshake', () => {
    const hello = parseClientHello(clientHello(profiles.chrome));
    expect(hello.alpn).toEqual(['h2', 'http/1.1']);
    expect(hello.hasServerName).toBe(true);
  });

  it('computes JA4 the way the specification describes', async () => {
    // A hand-made hello: two ciphers, three extensions, one of them GREASE.
    const hello = {
      ciphers: [0x0a0a, 0x1301, 0x1302],
      extensions: [0x0a0a, 0x0000, 0x0010, 0x000d],
      signatureSchemes: [0x0403, 0x0804],
      alpn: ['h2'],
      hasServerName: true,
    };
    const computed = await ja4(hello);

    // Two ciphers, three extensions once GREASE is dropped, ALPN `h2`.
    expect(computed.startsWith('t13d0203h2_')).toBe(true);
    // server_name and ALPN are counted above but left out of the hash, so the
    // only extension hashed here is signature_algorithms.
    const [, ciphers, extensions] = computed.split('_');
    expect(ciphers).toHaveLength(12);
    expect(extensions).toHaveLength(12);
  });

  it('writes the Akamai fingerprint in its usual shape', () => {
    expect(akamai(profiles.chrome.http2)).toBe('1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p');
    // Firefox and Safari differ in every field, which is the point of it.
    expect(akamai(profiles.firefox.http2)).not.toBe(akamai(profiles.safari.http2));
  });

  it('refuses something that is not a ClientHello', () => {
    expect(() => parseClientHello(new Uint8Array([1, 2, 3]))).toThrow(VerifyError);
  });

  it('notices when a profile drifts from what it claims', async () => {
    const drifted = {
      ...profiles.chrome,
      expected: { ...profiles.chrome.expected, ja4: 't13d0000h2_deadbeefcafe_deadbeefcafe' },
    };
    const verdict = await verifyProfile('drifted', drifted, clientHello(profiles.chrome));

    expect(verdict.ok).toBe(false);
    expect(verdict.ja4.ok).toBe(false);
    expect(verdict.akamai.ok).toBe(true);
  });
});
