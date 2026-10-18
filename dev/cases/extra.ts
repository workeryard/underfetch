/**
 * Live cases beyond plain HTTP: certificates that must fail, real sites that
 * run bot checks, and WebSocket.
 */

import { Session, websocket, type WorkerSessionDefaults } from '../../src/workers/index';
import { run, short, websocketKey, type Check, type Outcome } from './probe';
import * as badssl from '../fixtures/badssl-client';

/** HTTP/1.1 without TLS, which a profile's ALPN never reaches. */
export async function plainHttpCases(bin: string, profile: WorkerSessionDefaults['impersonate']) {
  const s = () => new Session({ timeoutMs: 25_000, retry: false, impersonate: profile });
  const out: Outcome[] = [];
  const add = async (group: string, name: string, check: Check) =>
    out.push(await run(group, name, check));

  // --- plain http -----------------------------------------------------------
  await add('http', 'plain http:// (HTTP/1.1, no TLS)', async () => {
    const r = await s().get(`${bin.replace('https:', 'http:')}/get`);
    return [r.status === 200, `status ${r.status}`];
  });
  await add('http', 'plain http:// chunked stream', async () => {
    const r = await s().get(`${bin.replace('https:', 'http:')}/stream/5`);
    const lines = (await r.text()).trim().split('\n').length;
    return [lines === 5, `${lines} lines`];
  });

  return out;
}

/** Certificates that must be refused, and one old-TLS server that must not. */
export async function tlsCases(profile: WorkerSessionDefaults['impersonate']) {
  const s = () => new Session({ timeoutMs: 15_000, retry: false, impersonate: profile });
  const out: Outcome[] = [];
  // A chain completed from AIA must not rescue any of these: each is wrong in
  // a way no missing intermediate explains. notl.org serves a certificate
  // for notl.com only, which Chrome rejects too.
  for (const host of [
    'expired.badssl.com',
    'self-signed.badssl.com',
    'wrong.host.badssl.com',
    'untrusted-root.badssl.com',
    'revoked.badssl.com',
    'www.notl.org',
  ]) {
    out.push(
      await run('tls', `${host} refused`, async () => {
        const revoked = host.startsWith('revoked');
        try {
          const r = await s().get(`https://${host}/`);
          return [
            revoked,
            `accepted, status ${r.status}${revoked ? ' (no revocation checks, like most clients)' : ''}`,
          ];
        } catch (error) {
          return [true, String(error).slice(0, 120)];
        }
      }),
    );
  }
  for (const [label, url] of [
    ['TLS 1.2-only server', 'https://tls-v1-2.badssl.com:1012/'],
    ['ECC certificate', 'https://ecc256.badssl.com/'],
    ['RSA 4096', 'https://rsa4096.badssl.com/'],
    ['SHA-256 chain', 'https://sha256.badssl.com/'],
    // The server sends its leaf alone; browsers fetch the rest (AIA).
    ['incomplete chain, completed as a browser would', 'https://incomplete-chain.badssl.com/'],
    ['leaf-only chain, one hop short (lincoln.ca)', 'https://www.lincoln.ca/'],
  ] as const) {
    out.push(
      await run('tls', label, async () => {
        const r = await s().get(url);
        await r.text();
        return [r.status === 200, `status ${r.status}`];
      }),
    );
  }
  // What a session trusts and presents, set by the caller.
  const loose = () =>
    new Session({ timeoutMs: 15_000, retry: false, impersonate: profile, verify: false });
  for (const host of ['self-signed.badssl.com', 'wrong.host.badssl.com', 'expired.badssl.com']) {
    out.push(
      await run('tls', `${host} taken with verify: false`, async () => {
        const r = await loose().get(`https://${host}/`);
        await r.text();
        return [r.status === 200, `status ${r.status}`];
      }),
    );
  }
  // client.badssl.com answers 400 to a connection that showed no certificate.
  for (const [label, clientCert] of [
    ['client.badssl.com without a certificate: 400', undefined],
    ['client.badssl.com with its certificate: 200', badssl],
  ] as const) {
    out.push(
      await run('tls', label, async () => {
        const r = await new Session({
          timeoutMs: 15_000,
          retry: false,
          impersonate: profile,
          clientCert,
        }).get('https://client.badssl.com/');
        await r.text();
        return [r.status === (clientCert ? 200 : 400), `status ${r.status}`];
      }),
    );
  }
  return out;
}

/** Real sites, some behind bot checks, to see what a profile gets back. */
export async function siteCases(profile: WorkerSessionDefaults['impersonate']) {
  const out: Outcome[] = [];
  for (const url of [
    'https://www.google.com/',
    'https://github.com/',
    'https://www.cloudflare.com/',
    'https://www.amazon.com/',
    'https://www.wikipedia.org/',
    'https://discord.com/',
    'https://www.reddit.com/',
    'https://chatgpt.com/',
  ]) {
    out.push(
      await run('sites', url, async () => {
        const r = await new Session({ timeoutMs: 20_000, retry: false, impersonate: profile }).get(
          url,
        );
        const text = await r.text();
        // Read the title: a real page may mention "captcha" anywhere in its code.
        const title = /<title[^>]*>([^<]*)</i.exec(text)?.[1]?.trim() ?? '';
        const challenged = /just a moment|attention required|robot|captcha/i.test(title);
        return [
          r.status < 400 && !challenged,
          `status ${r.status}, ${text.length} bytes, title ${JSON.stringify(title.slice(0, 50))}${challenged ? ', CHALLENGE page' : ''}`,
        ];
      }),
    );
  }
  // httpbin has no zstd endpoint. Facebook answers zstd to anyone offering
  // only that (checked with curl); cloudflare.com, for one, answers identity.
  out.push(
    await run('encoding', 'zstd undone', async () => {
      const r = await new Session({ timeoutMs: 20_000, retry: false, impersonate: profile }).get(
        'https://www.facebook.com/',
        { headers: { 'accept-encoding': 'zstd' } },
      );
      const text = await r.text();
      // Any status will do: without a profile Facebook refuses with a 400,
      // and that page arrives in zstd too. What is checked is that it reads.
      return [
        /<html/i.test(text.slice(0, 2000)),
        `status ${r.status}, content-encoding left=${r.headers.get('content-encoding')}, first bytes ${short(text.slice(0, 30))}`,
      ];
    }),
  );
  return out;
}

/**
 * WebSocket, which impers has and this does not. Three readings: what the
 * platform's own `fetch` does (a working socket, but not ours), and what an
 * Upgrade request through underfetch does today, over each ALPN.
 */
export async function websocketCases(profile: WorkerSessionDefaults['impersonate']) {
  const out: Outcome[] = [];
  const url = 'https://echo.websocket.org/';
  const upgrade = {
    upgrade: 'websocket',
    connection: 'Upgrade',
    'sec-websocket-key': websocketKey(),
    'sec-websocket-version': '13',
  };

  out.push(
    await run('websocket', 'platform fetch() upgrade (baseline, not underfetch)', async () => {
      const r = await fetch(url, { headers: upgrade });
      const ws = (r as Response & { webSocket?: (WebSocket & { accept(): void }) | null })
        .webSocket;
      if (!ws) return [false, `status ${r.status}, no webSocket`];
      ws.accept();
      const echoed = new Promise<string>((resolve) => {
        const seen: string[] = [];
        ws.addEventListener('message', (e) => {
          seen.push(String(e.data));
          if (seen.includes('ping-from-probe')) resolve(seen.join(' | '));
        });
      });
      ws.send('ping-from-probe');
      const got = await echoed;
      ws.close(1000, 'done');
      return [true, `101, echoed: ${got.slice(0, 120)}`];
    }),
  );

  const label = typeof profile === 'string' ? profile : 'no profile';
  out.push(
    await run('websocket', `underfetch echo, text and binary (${label})`, async () => {
      const ws = await websocket('wss://echo.websocket.org/', {
        impersonate: profile,
        timeoutMs: 10_000,
      });
      // echo.websocket.org greets first, with the name of the server.
      const greeting = await ws.recv();
      await ws.send('ping-from-underfetch');
      const text = await ws.recv();
      await ws.send(new Uint8Array([1, 2, 3, 250]));
      const binary = await ws.recv();
      const big = 'x'.repeat(100_000);
      await ws.send(big);
      const echoedBig = await ws.recv();
      const closed = await ws.close(1000, 'done');
      const ok =
        text?.type === 'text' &&
        text.data === 'ping-from-underfetch' &&
        binary?.type === 'binary' &&
        [...binary.data].join() === '1,2,3,250' &&
        echoedBig?.data === big;
      return [
        ok,
        `deflate ${ws.compressed}, greeting ${short(greeting?.data)}, text ${short(text?.data)}, 100 KB ${echoedBig?.data === big}, closed ${short(closed)}`,
      ];
    }),
  );
  // Both compress (checked with a raw client: RSV1 set). Bitstamp keeps its
  // window across messages and fragments them; Coinbase starts each afresh.
  for (const [name, url, subscribe] of [
    [
      'bitstamp, deflate with context kept',
      'wss://ws.bitstamp.net/',
      { event: 'bts:subscribe', data: { channel: 'order_book_btcusd' } },
    ],
    [
      'coinbase, deflate without context',
      'wss://ws-feed.exchange.coinbase.com/',
      { type: 'subscribe', product_ids: ['BTC-USD'], channels: ['ticker'] },
    ],
  ] as const) {
    out.push(
      await run('websocket', `${name} (${label})`, async () => {
        const ws = await websocket(url, { impersonate: profile, timeoutMs: 10_000 });
        await ws.send(JSON.stringify(subscribe));
        let parsed = 0;
        for (let i = 0; i < 6; i++) {
          const message = await ws.recv();
          if (message?.type !== 'text') break;
          JSON.parse(message.data);
          parsed++;
        }
        await ws.close();
        return [ws.compressed && parsed === 6, `deflate ${ws.compressed}, ${parsed} JSON messages`];
      }),
    );
  }
  return out;
}
