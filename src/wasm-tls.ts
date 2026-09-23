/**
 * The TLS session backed by `rust-tls/`.
 *
 * This is the one module that needs a bundler: the `.wasm` import is turned
 * into a `WebAssembly.Module` by Wrangler and Vite. Everything else in the
 * package stays plain TypeScript, so only this file cares how it is built.
 */

import { initSync, TlsClient } from '../rust-tls/pkg/underfetch_tls';
import wasm from '../rust-tls/pkg/underfetch_tls_bg.wasm';
import type { TlsFactory } from './tls';

/**
 * `initSync` returns immediately once the module is instantiated, so calling it
 * per connection costs nothing and saves us holding state of our own.
 */
export const wasmTls: TlsFactory = (hostname, alpn) => {
  initSync({ module: wasm });
  return new TlsClient(hostname, alpn);
};
