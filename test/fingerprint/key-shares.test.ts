import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { GREASE } from '../../src/fingerprint/grease';
import { encodeExtensions, profiles, type Impersonation } from '../../src/fingerprint/profiles';
import { parseClientHello } from '../../src/fingerprint/verify';
import { initSync, TlsClient } from '../../rust-tls/pkg/underfetch_tls';

initSync({
  module: new WebAssembly.Module(
    readFileSync(
      fileURLToPath(new URL('../../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url)),
    ),
  ),
});

/** What each share weighs on the wire, as the browsers send them. */
const LENGTH: Record<number, number> = { 0x11ec: 1216, 0x001d: 32, 0x0017: 65 };

function sharesOf(as: Impersonation) {
  const client = new TlsClient(
    'example.com',
    as.alpn.join(','),
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
    as.greaseNamedGroup,
    as.extensionOrder === undefined ? undefined : new Uint16Array(as.extensionOrder),
    as.namedGroups === undefined ? undefined : new Uint16Array(as.namedGroups),
    undefined,
    undefined,
    undefined,
    as.keyShares === undefined ? undefined : new Uint16Array(as.keyShares),
  );
  const hello = parseClientHello(client.outgoing());
  client.free();
  // GREASE values differ between captures and connections; compare the slot.
  return (hello.keyShares ?? []).map(({ group, length }) => ({
    group: (GREASE as readonly number[]).includes(group) ? GREASE[0] : group,
    length,
  }));
}

describe('key shares', () => {
  it('are the groups and sizes each captured browser sent', () => {
    for (const [name, profile] of Object.entries(profiles)) {
      const expected = (profile.keyShares ?? []).map((group) => ({
        group,
        length: (GREASE as readonly number[]).includes(group) ? 1 : LENGTH[group],
      }));
      expect(sharesOf(profile), name).toEqual(expected);
    }
  });

  it('lead with X25519MLKEM768 where the browser does, and only there', () => {
    expect(sharesOf(profiles.chrome).map((s) => s.group)).toEqual([GREASE[0], 0x11ec, 0x001d]);
    expect(sharesOf(profiles.firefox).map((s) => s.group)).toEqual([0x11ec, 0x001d, 0x0017]);
    // Chrome 124 offered Kyber's draft, which cannot be made, so X25519 alone.
    expect(sharesOf(profiles.chrome124).map((s) => s.group)).toEqual([GREASE[0], 0x001d]);
  });
});
