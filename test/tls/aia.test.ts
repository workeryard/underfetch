import { describe, expect, it } from 'vitest';
import { fetchOver } from '../../src/client/fetch';
import type { ByteSocket, Dial } from '../../src/net/socket';
import {
  caIssuersUrl,
  certificatesIn,
  chaseIssuers,
  decodeCertificates,
  encodeCertificates,
  MAX_HOPS,
} from '../../src/tls/aia';
import type { TlsFactory, TlsSession } from '../../src/tls/tunnel';

const ascii = (text: string) => [...new TextEncoder().encode(text)];

/** An AccessDescription as it sits in a certificate: method OID, then a URI. */
function access(method: 0x01 | 0x02, url: string): number[] {
  const oid = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, method];
  const uri = [0x86, url.length, ...ascii(url)];
  return [0x30, oid.length + uri.length, ...oid, ...uri];
}

/** Enough of a certificate for the byte search: a DER prefix and an AIA. */
const cert = (...entries: number[][]) =>
  new Uint8Array([0x30, 0x82, 0x01, 0x00, ...entries.flat(), 0x05, 0x00]);

describe('AIA', () => {
  it('reads the CA Issuers address and skips the OCSP one', () => {
    const der = cert(
      access(0x01, 'http://ocsp.example/'),
      access(0x02, 'http://ca.example/issuer.der'),
    );
    expect(caIssuersUrl(der)).toBe('http://ca.example/issuer.der');
    expect(caIssuersUrl(cert(access(0x01, 'http://ocsp.example/')))).toBeUndefined();
  });

  it('takes DER and PEM answers, and refuses a PKCS#7 bundle', () => {
    const der = cert();
    expect(certificatesIn(der)).toEqual([der]);

    const pem = `-----BEGIN CERTIFICATE-----\n${btoa(String.fromCharCode(...der))}\n-----END CERTIFICATE-----\n`;
    expect(certificatesIn(new TextEncoder().encode(pem))).toEqual([der]);

    const bundle = new Uint8Array([
      0x30, 0x82, 0x02, 0x00, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ]);
    expect(certificatesIn(bundle)).toEqual([]);
  });

  it('round-trips certificates across the boundary', () => {
    const certs = [cert(), cert(access(0x02, 'http://x/'))];
    expect(decodeCertificates(encodeCertificates(certs))).toEqual(certs);
  });

  it('walks up hop by hop, and stops at a loop or the hop limit', async () => {
    const top = cert();
    const middle = cert(access(0x02, 'http://ca.example/top'));
    const leaf = cert(access(0x02, 'http://ca.example/middle'));
    const served: Record<string, Uint8Array> = {
      'http://ca.example/middle': middle,
      'http://ca.example/top': top,
    };
    const asked: string[] = [];
    const fetchCert = (url: string) => {
      asked.push(url);
      return Promise.resolve(served[url] ?? new Uint8Array(0));
    };

    expect(await chaseIssuers([leaf], fetchCert)).toEqual([middle, top]);
    expect(asked).toEqual(['http://ca.example/middle', 'http://ca.example/top']);

    const selfNaming = cert(access(0x02, 'http://ca.example/loop'));
    served['http://ca.example/loop'] = selfNaming;
    asked.length = 0;
    await chaseIssuers([selfNaming], fetchCert);
    expect(asked).toHaveLength(1);

    let n = 0;
    const endless = () => Promise.resolve(cert(access(0x02, `http://ca.example/${n++}`)));
    expect(
      await chaseIssuers([cert(access(0x02, 'http://ca.example/start'))], endless),
    ).toHaveLength(MAX_HOPS);
  });
});

/**
 * A TLS session whose server sends its leaf alone: it fails the way rustls
 * does until it is handed the missing issuer.
 */
class ShortChain implements TlsSession {
  handshaking = true;
  constructor(
    private readonly leaf: Uint8Array,
    private readonly completed: boolean,
  ) {}
  receive(data: Uint8Array): number {
    if (this.handshaking) {
      if (!this.completed) {
        // A string, not an Error: that is what wasm-bindgen throws from Rust.
        // eslint-disable-next-line @typescript-eslint/only-throw-error
        throw 'TLS session failed: invalid peer certificate: UnknownIssuer';
      }
      this.handshaking = false;
      return data.length;
    }
    this.#plain.push(...data);
    return data.length;
  }
  #plain: number[] = [];
  outgoing = () => new Uint8Array(0);
  send(): void {}
  plaintext(): Uint8Array {
    const out = new Uint8Array(this.#plain);
    this.#plain = [];
    return out;
  }
  presentedChain = () => encodeCertificates([this.leaf]);
  close(): void {}
}

function socketAnswering(...chunks: string[] | Uint8Array[]): ByteSocket {
  return {
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk);
        }
        controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>(),
    close: () => Promise.resolve(),
  };
}

describe('fetchOver with a short chain', () => {
  const issuer = cert();
  const leaf = cert(access(0x02, 'http://ca.example/issuer.der'));
  const issuerAnswer = new Uint8Array([
    ...ascii(`HTTP/1.1 200 OK\r\nContent-Length: ${issuer.length}\r\n\r\n`),
    ...issuer,
  ]);

  const setUp = () => {
    const dialled: string[] = [];
    const dial: Dial = (hostname) => {
      dialled.push(hostname);
      return Promise.resolve(
        hostname === 'ca.example'
          ? socketAnswering(issuerAnswer)
          : socketAnswering('\x16', 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
      );
    };
    const given: (readonly Uint8Array[] | undefined)[] = [];
    const tls: TlsFactory = (_hostname, _alpn, options) => {
      const intermediates = options?.intermediates;
      given.push(intermediates);
      return new ShortChain(
        leaf,
        (intermediates ?? []).some((c) => c.length === issuer.length),
      );
    };
    return { dial, tls, dialled, given };
  };

  it('fetches the issuer the leaf names and connects again with it', async () => {
    const { dial, tls, dialled, given } = setUp();
    const response = await fetchOver(new Request('https://short.example/'), { dial, tls });

    expect(await response.text()).toBe('ok');
    expect(dialled).toEqual(['short.example', 'ca.example', 'short.example']);
    expect(given.at(-1)).toEqual([issuer]);
  });

  it('does not chase when asked not to', async () => {
    const { dial, tls, dialled } = setUp();
    await expect(
      fetchOver(new Request('https://short.example/'), { dial, tls, completeChains: false }),
    ).rejects.toMatch(/UnknownIssuer/);
    expect(dialled).toEqual(['short.example']);
  });
});
