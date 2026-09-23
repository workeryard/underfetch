/**
 * The TLS session backed by `rust-tls/`.
 *
 * This is the one module that needs a bundler: the `.wasm` import is turned
 * into a `WebAssembly.Module` by Wrangler and Vite. Everything else in the
 * package stays plain TypeScript, so only this file cares how it is built.
 */

import { encodeExtensions, type Impersonation } from './impersonate';
import { initSync, TlsClient } from '../rust-tls/pkg/underfetch_tls';
import wasm from '../rust-tls/pkg/underfetch_tls_bg.wasm';
import type { TlsFactory } from './tls';

/**
 * `initSync` returns immediately once the module is instantiated, so calling it
 * per connection costs nothing and saves us holding state of our own.
 */
function client(hostname: string, alpn: string | undefined, as: Impersonation | undefined) {
  initSync({ module: wasm });
  if (as === undefined) return new TlsClient(hostname, alpn);
  return new TlsClient(
    hostname,
    alpn ?? as.alpn.join(','),
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
  );
}

/** TLS that looks like whatever `as` describes, or like rustls when it is absent. */
export const impersonating =
  (as: Impersonation | undefined): TlsFactory =>
  (hostname, alpn) =>
    client(hostname, alpn, as);

/** TLS with rustls' own ClientHello, which is safe and instantly recognisable. */
export const wasmTls: TlsFactory = (hostname, alpn) => client(hostname, alpn, undefined);
