import { describe, expect, it } from 'vitest';
import { fetchOver } from '../../src/client/fetch';
import type { ByteSocket, Dial } from '../../src/net/socket';
import type { TlsFactory, TlsOptions, TlsSession } from '../../src/tls/tunnel';

/** A session that fails its handshake with `failure` until `cured` says otherwise. */
class Failing implements TlsSession {
  handshaking = true;
  #plain: number[] = [];
  constructor(
    private readonly failure: string,
    private readonly cured: boolean,
  ) {}
  receive(data: Uint8Array): number {
    if (this.handshaking) {
      // A string, not an Error: that is what wasm-bindgen throws from Rust.
      // eslint-disable-next-line @typescript-eslint/only-throw-error
      if (!this.cured) throw this.failure;
      this.handshaking = false;
      return data.length;
    }
    this.#plain.push(...data);
    return data.length;
  }
  outgoing = () => new Uint8Array(0);
  send(): void {}
  plaintext(): Uint8Array {
    const out = new Uint8Array(this.#plain);
    this.#plain = [];
    return out;
  }
  close(): void {}
}

const dial: Dial = () =>
  Promise.resolve<ByteSocket>({
    readable: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([0x16]));
        controller.enqueue(
          new TextEncoder().encode('HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'),
        );
        controller.close();
      },
    }),
    writable: new WritableStream<Uint8Array>(),
    close: () => Promise.resolve(),
  });

function factory(failure: string, cure: (options: TlsOptions) => boolean) {
  const given: TlsOptions[] = [];
  const tls: TlsFactory = (_hostname, _alpn, options = {}) => {
    given.push(options);
    return new Failing(failure, cure(options));
  };
  return { tls, given };
}

const UNCHECKABLE = 'TLS session failed: peer misbehaved: SignedHandshakeWithUnadvertisedSigScheme';

describe('a second connection', () => {
  it('offers only checkable signatures after a server picked one we cannot check', async () => {
    const { tls, given } = factory(UNCHECKABLE, (o) => o.verifiableSignatures === true);
    const response = await fetchOver(new Request('https://old.example/'), { dial, tls });

    expect(await response.text()).toBe('ok');
    expect(given.map((o) => o.verifiableSignatures ?? false)).toEqual([false, true]);
  });

  it('tries each remedy once, and then gives the error back', async () => {
    const { tls, given } = factory(UNCHECKABLE, () => false);
    await expect(fetchOver(new Request('https://old.example/'), { dial, tls })).rejects.toMatch(
      /UnadvertisedSigScheme/,
    );
    expect(given).toHaveLength(2);
  });

  it('is not made for a failure no remedy explains', async () => {
    const expired = 'TLS session failed: invalid peer certificate: certificate expired';
    const { tls, given } = factory(expired, () => false);
    await expect(fetchOver(new Request('https://old.example/'), { dial, tls })).rejects.toMatch(
      /expired/,
    );
    expect(given).toHaveLength(1);
  });
});
