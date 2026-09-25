import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FingerprintError, withFingerprints } from '../../src/fingerprint/custom';
import { encodeExtensions, profiles, type Impersonation } from '../../src/fingerprint/profiles';
import { ja3, ja4, parseClientHello, verifyProfile } from '../../src/fingerprint/verify';
import { initSync, TlsClient } from '../../rust-tls/pkg/underfetch_tls';

/**
 * A profile built from the two strings tls.peet.ws shows. The JA3 strings
 * below are the real browsers', computed from curl-impersonate's captures.
 */

const wasm = new WebAssembly.Module(
  readFileSync(
    fileURLToPath(new URL('../../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url)),
  ),
);

function hello(as: Impersonation): Uint8Array {
  initSync({ module: wasm });
  return new TlsClient(
    'example.com',
    as.alpn.join(','),
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
    as.greaseNamedGroup,
    as.extensionOrder === undefined ? undefined : new Uint16Array(as.extensionOrder),
    as.namedGroups === undefined ? undefined : new Uint16Array(as.namedGroups),
  ).outgoing();
}

const CHROME_150 = {
  ja3: '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17613-45-27-51-43-65281-65037-23-11-5-35-10-18-16-13-0,4588-29-23-24,0',
  akamai: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p',
};
const FIREFOX_144 = {
  ja3: '771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0',
  akamai: '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s',
};

describe('withFingerprints', () => {
  it("sends Chrome 150's JA3 exactly, its post-quantum group included", async () => {
    const as = withFingerprints(profiles.chrome150, CHROME_150);
    const sent = ja3(parseClientHello(hello(as)));

    expect(sent).toBe(CHROME_150.ja3);
    expect(as.expected.ja3).toBe(sent);
    expect((await verifyProfile('chrome', as, hello(as))).ok).toBe(true);
  });

  it('builds Firefox from its strings on a Chrome base, borrowing only what they lack', async () => {
    const as = withFingerprints(profiles.chrome150, FIREFOX_144);
    const sent = parseClientHello(hello(as));

    expect(ja3(sent)).toBe(FIREFOX_144.ja3);
    // Bodies Chrome has none of, delegated credentials and the record size
    // limit, came from the defaults; the signature algorithms from the base.
    expect(sent.extensions).toContain(0x0022);
    expect(sent.signatureSchemes).toEqual([...profiles.chrome150.signatureSchemes]);
    expect(as.http2.pseudoHeaderOrder).toEqual(['m', 'p', 'a', 's']);
    expect((await verifyProfile('firefox', as, hello(as))).ok).toBe(true);
  });

  it("shuffles as Chrome does when asked, keeping Chrome 150's JA4 and claiming no JA3", async () => {
    const as = withFingerprints(profiles.chrome150, { ...CHROME_150, shuffle: true });
    expect(as.extensionOrder).toBeUndefined();
    expect(as.expected.ja3).toBeUndefined();
    expect(await ja4(parseClientHello(hello(as)))).toBe(profiles.chrome150.expected.ja4);
  });

  it('changes only the HTTP/2 side given an Akamai string alone', () => {
    const akamai = '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p';
    const as = withFingerprints(profiles.chrome131, { akamai });
    expect(as.expected.akamai).toBe(akamai);
    expect(as.expected.ja4).toBe(profiles.chrome131.expected.ja4);
    expect(as.ciphers).toEqual(profiles.chrome131.ciphers);
  });

  it('refuses what it cannot send, and says what', () => {
    const withUnknown = { ...CHROME_150, ja3: CHROME_150.ja3.replace('-0,', '-0-49,') };
    expect(() => withFingerprints(profiles.chrome150, withUnknown)).toThrow(
      /cannot send extension 49/,
    );

    const withPriority = { ...FIREFOX_144, akamai: '1:65536|12517377|3:0:0:201|m,p,a,s' };
    expect(() => withFingerprints(profiles.firefox144, withPriority)).toThrow(FingerprintError);

    const noX25519 = { ...CHROME_150, ja3: CHROME_150.ja3.replace('4588-29-23-24', '23-24') };
    expect(() => withFingerprints(profiles.chrome150, noX25519)).toThrow(/X25519/);

    expect(() => withFingerprints(profiles.chrome, { ja3: 'nonsense' })).toThrow(FingerprintError);
  });
});
