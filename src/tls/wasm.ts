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
import { customTrust, trustArguments, type TrustOptions } from './trust';
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
  resume = true,
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
      undefined,
      resume,
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
    as.keyShares === undefined ? undefined : new Uint16Array(as.keyShares),
    resume,
  );
}

/**
 * A place for one session's tickets, so a second connection to a host resumes
 * the first, as a returning browser's does. `export()` and `import()` carry
 * them past the isolate; the tickets go when the store is collected. It also
 * holds whom the session trusts and the certificate it presents; see
 * `TrustOptions`.
 */
export function ticketStore(trust?: TrustOptions): TicketStore {
  initSync({ module: wasm });
  return new TicketStore(...trustArguments(trust));
}

/**
 * TLS that looks like whatever `as` describes, or like rustls when it is
 * absent. Its connections share `tickets` — by default a store of their own,
 * made on the first connection; `false` never resumes. `trust` is for the
 * store made here; a store passed in already has its own.
 */
export function impersonating(
  as: Impersonation | undefined,
  tickets: TicketStore | boolean = true,
  trust?: TrustOptions,
): TlsFactory {
  if (typeof tickets === 'object' && customTrust(trust)) {
    throw new TypeError(
      'a ticket store passed in has its trust already; give trust when making it',
    );
  }
  let store = typeof tickets === 'object' ? tickets : undefined;
  // A store is where trust lives, so a session that never resumes but trusts
  // differently still gets one, used for that alone.
  const resume = tickets !== false;
  const needed = resume || customTrust(trust);
  return (hostname, alpn, options) => {
    if (needed) store ??= ticketStore(trust);
    return client(hostname, alpn, as, options, store?.id, resume);
  };
}

/** TLS with rustls' own ClientHello, which is safe and instantly recognisable. Never resumes. */
export const wasmTls: TlsFactory = (hostname, alpn, options) =>
  client(hostname, alpn, undefined, options);
