/**
 * Live cases beyond plain HTTP: certificates that must fail, real sites that
 * run bot checks, and WebSocket.
 */

import { Session, type WorkerSessionDefaults } from '../src/workers/index';
import { run, short, websocketKey, type Check, type Outcome } from './probe';

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
  for (const host of ['expired', 'self-signed', 'wrong.host', 'untrusted-root', 'revoked']) {
    out.push(
      await run('tls', `${host}.badssl.com refused`, async () => {
        try {
          const r = await s().get(`https://${host}.badssl.com/`);
          return [
            host === 'revoked',
            `accepted, status ${r.status}${host === 'revoked' ? ' (no revocation checks, like most clients)' : ''}`,
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
  ] as const) {
    out.push(
      await run('tls', label, async () => {
        const r = await s().get(url);
        await r.text();
        return [r.status === 200, `status ${r.status}`];
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

  out.push(
    await run(
      'websocket',
      `underfetch Upgrade request (${typeof profile === 'string' ? profile : 'no profile'})`,
      async () => {
        const r = await new Session({ timeoutMs: 10_000, retry: false, impersonate: profile }).get(
          url,
          {
            headers: upgrade,
          },
        );
        const body = r.body ? (await r.text()).slice(0, 80) : '';
        return [
          r.status === 101,
          `status ${r.status} upgrade=${r.headers.get('upgrade')} body=${short(body)}`,
        ];
      },
    ),
  );
  return out;
}
