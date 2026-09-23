// Prints what each profile actually puts on the wire, next to what it claims.
// No network: both fingerprints are computed from bytes generated here.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodeExtensions, profiles } from '../src/fingerprint/profiles';
import { verifyProfile } from '../src/fingerprint/verify';
import { initSync, TlsClient } from '../rust-tls/pkg/underfetch_tls';

initSync({
  module: new WebAssembly.Module(
    readFileSync(fileURLToPath(new URL('../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url))),
  ),
});

let failed = false;
for (const [name, profile] of Object.entries(profiles)) {
  const session = new TlsClient(
    'example.com',
    profile.alpn.join(','),
    new Uint16Array(profile.ciphers),
    new Uint16Array(profile.signatureSchemes),
    encodeExtensions(profile.extensions()),
    profile.greaseNamedGroup,
    profile.extensionOrder === undefined ? undefined : new Uint16Array(profile.extensionOrder),
  );
  const verdict = await verifyProfile(name, profile, session.outgoing());
  session.close();

  console.log(`${verdict.ok ? 'ok  ' : 'FAIL'} ${name}`);
  console.log(`       ja4    ${verdict.ja4.got}`);
  if (!verdict.ja4.ok) console.log(`       wanted ${verdict.ja4.want}`);
  console.log(`       akamai ${verdict.akamai.got}`);
  if (!verdict.akamai.ok) console.log(`       wanted ${verdict.akamai.want}`);
  failed ||= !verdict.ok;
}
process.exit(failed ? 1 : 0);
