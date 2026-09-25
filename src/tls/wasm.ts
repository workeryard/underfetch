/**
 * The TLS session backed by `rust-tls/`.
 *
 * This is the one module that needs a bundler: the `.wasm` import is turned
 * into a `WebAssembly.Module` by Wrangler and Vite. Everything else in the
 * package stays plain TypeScript, so only this file cares how it is built.
 */

import { encodeExtensions, type Impersonation } from '../fingerprint/profiles';
import { initSync, TicketStore, TlsClient } from '../../rust-tls/pkg/underfetch_tls';
import { encodeCertificates } from './aia';
import wasm from '../../rust-tls/pkg/underfetch_tls_bg.wasm';
import type { TlsFactory, TlsOptions } from './tunnel';

/**
 * `initSync` returns immediately once the module is instantiated, so calling it
 * per connection costs nothing and saves us holding state of our own.
 */
function client(
  hostname: string,
  alpn: string | undefined,
  as: Impersonation | undefined,
  { intermediates, verifiableSignatures }: TlsOptions = {},
  tickets?: number,
) {
  initSync({ module: wasm });
  const extra = intermediates?.length ? encodeCertificates(intermediates) : undefined;
  if (as === undefined) {
    return new TlsClient(
      hostname,
      alpn ?? 'h2,http/1.1',
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      extra,
      verifiableSignatures,
      tickets,
    );
  }
  return new TlsClient(
    hostname,
    alpn ?? as.alpn.join(','),
    new Uint16Array(as.ciphers),
    new Uint16Array(as.signatureSchemes),
    encodeExtensions(as.extensions()),
    as.greaseNamedGroup,
    as.extensionOrder === undefined ? undefined : new Uint16Array(as.extensionOrder),
    as.namedGroups === undefined ? undefined : new Uint16Array(as.namedGroups),
    extra,
    verifiableSignatures,
    tickets,
  );
}

/**
 * Session tickets for one factory's connections, made on the first of them.
 * A second connection to a host then resumes the first, as a returning
 * browser's does; the tickets go when the factory does.
 */
function ticketsFor(resume: boolean): () => number | undefined {
  if (!resume) return () => undefined;
  let store: TicketStore | undefined;
  return () => {
    initSync({ module: wasm });
    store ??= new TicketStore();
    return store.id;
  };
}

/**
 * TLS that looks like whatever `as` describes, or like rustls when it is
 * absent. Connections made through one factory share session tickets unless
 * `resume` is false, so each `Session` resumes only its own.
 */
export function impersonating(as: Impersonation | undefined, resume = true): TlsFactory {
  const tickets = ticketsFor(resume);
  return (hostname, alpn, options) => client(hostname, alpn, as, options, tickets());
}

/** TLS with rustls' own ClientHello, which is safe and instantly recognisable. Never resumes. */
export const wasmTls: TlsFactory = (hostname, alpn, options) =>
  client(hostname, alpn, undefined, options);
