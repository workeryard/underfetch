import { readFileSync } from 'node:fs';
import { connect, type Socket } from 'node:net';
import { createServer, type TLSSocket } from 'node:tls';
import { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fetchOver } from '../../src/client/fetch';
import type { ByteSocket, Dial } from '../../src/net/socket';
import { trustArguments, type TrustOptions } from '../../src/tls/trust';
import type { TlsFactory } from '../../src/tls/tunnel';
import { initSync, TicketStore, TlsClient } from '../../rust-tls/pkg/underfetch_tls';

/**
 * Against a real TLS server, node's, on a certificate from a CA of our own
 * (see fixtures/README.md): the web PKI's roots refuse it, the CA accepts it,
 * and a server that asks who is calling gets the client certificate.
 */

const fixture = (name: string) =>
  readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const text = (name: string) => fixture(name).toString('utf8');

initSync({
  module: new WebAssembly.Module(
    readFileSync(
      fileURLToPath(new URL('../../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url)),
    ),
  ),
});

/** rustls, as the Workers adapter builds it, with `trust` in its store. */
function tlsWith(trust: TrustOptions): TlsFactory {
  const store = new TicketStore(...trustArguments(trust));
  return (hostname, alpn) =>
    new TlsClient(
      hostname,
      alpn ?? 'http/1.1',
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      store.id,
    );
}

/** A node socket, as a `ByteSocket`. */
const dialTo =
  (port: number): Dial =>
  () =>
    new Promise((resolve, reject) => {
      const socket: Socket = connect(port, '127.0.0.1', () => {
        const wrapped: ByteSocket = {
          readable: Readable.toWeb(socket) as ReadableStream<Uint8Array>,
          writable: Writable.toWeb(socket) as WritableStream<Uint8Array>,
          close: () => Promise.resolve(void socket.destroy()),
        };
        resolve(wrapped);
      });
      socket.once('error', reject);
    });

/** Answers each request with who the client said it was, if anyone. */
function server(requestCert: boolean) {
  const tls = createServer(
    {
      key: fixture('server.key'),
      cert: fixture('server.pem'),
      ca: fixture('ca.pem'),
      requestCert,
      rejectUnauthorized: requestCert,
    },
    (socket: TLSSocket) => {
      socket.once('data', () => {
        const who = String(socket.getPeerCertificate()?.subject?.CN ?? 'nobody');
        socket.end(
          `HTTP/1.1 200 OK\r\nContent-Length: ${who.length}\r\nConnection: close\r\n\r\n${who}`,
        );
      });
      socket.on('error', () => undefined);
    },
  );
  return tls;
}

const servers = { open: server(false), mutual: server(true) };
const ports = { open: 0, mutual: 0 };

beforeAll(async () => {
  for (const name of ['open', 'mutual'] as const) {
    await new Promise<void>((resolve) => servers[name].listen(0, '127.0.0.1', resolve));
    ports[name] = (servers[name].address() as { port: number }).port;
  }
});
afterAll(() => {
  servers.open.close();
  servers.mutual.close();
});

const ask = (which: 'open' | 'mutual', trust: TrustOptions, host = 'localhost') =>
  fetchOver(new Request(`https://${host}/`), {
    dial: dialTo(ports[which]),
    tls: tlsWith(trust),
    completeChains: false,
  }).then((response) => response.text());

describe('whom a session trusts', () => {
  it('refuses a private CA by default, as a browser would', async () => {
    await expect(ask('open', {})).rejects.toThrow(/UnknownIssuer/);
  });

  it('accepts it given the CA, in PEM or in DER', async () => {
    expect(await ask('open', { ca: text('ca.pem') })).toBe('nobody');
    expect(await ask('open', { ca: [new Uint8Array(fixture('ca.der'))] })).toBe('nobody');
  });

  it('still checks the name against a CA it was given', async () => {
    await expect(ask('open', { ca: text('ca.pem') }, 'elsewhere.example')).rejects.toThrow(
      /not valid for name/,
    );
  });

  it('takes anything when told not to verify, the wrong name included', async () => {
    expect(await ask('open', { verify: false }, 'elsewhere.example')).toBe('nobody');
  });
});

describe('a client certificate', () => {
  const clientCert = { cert: text('client.pem'), key: text('client.key') };

  it('is what a server that asks for one is shown', async () => {
    expect(await ask('mutual', { ca: text('ca.pem'), clientCert })).toBe('underfetch client');
  });

  it('takes its key in DER as well', async () => {
    const der = { cert: text('client.pem'), key: new Uint8Array(fixture('client.key.der')) };
    expect(await ask('mutual', { ca: text('ca.pem'), clientCert: der })).toBe('underfetch client');
  });

  it('is missed by a server that demands one when there is none', async () => {
    await expect(ask('mutual', { ca: text('ca.pem') })).rejects.toThrow();
  });

  it('is refused when it is not whole', () => {
    expect(() => tlsWith({ clientCert: { cert: '', key: text('client.key') } })).toThrow(
      /chain is empty/,
    );
    expect(() => tlsWith({ clientCert: { cert: text('client.pem'), key: 'not a key' } })).toThrow(
      /private key/,
    );
    expect(() =>
      tlsWith({ ca: '-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----' }),
    ).toThrow(/CA certificate/);
  });
});
