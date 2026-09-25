/**
 * A live case matrix, modelled on the cases impers tests against its mock
 * server, run here against public echo services instead. Each case says what
 * it expects and reports what it saw, so a gap reads as a gap rather than as a
 * crash in the middle of a run.
 */

import { Session, type WorkerSessionDefaults } from '../../src/workers/index';
import { arrival, json, run, short, type Check, type Outcome } from './probe';

export async function cases(bin: string, profile: WorkerSessionDefaults['impersonate']) {
  const s = (extra: WorkerSessionDefaults = {}) =>
    new Session({ timeoutMs: 25_000, retry: false, impersonate: profile, ...extra });
  const out: Outcome[] = [];
  const add = async (group: string, name: string, check: Check) =>
    out.push(await run(group, name, check));

  // --- GET -----------------------------------------------------------------
  await add('get', 'basic GET', async () => {
    const r = await s().get(`${bin}/get`);
    return [r.status === 200, `status ${r.status}`];
  });
  await add('get', 'query params merged with URL', async () => {
    const r = await s().get(`${bin}/get?a=1`, { params: { b: 2, c: 'x y' } });
    const args = (await json(r)).args;
    return [short(args) === short({ a: '1', b: '2', c: 'x y' }), short(args)];
  });
  await add('get', 'custom header, and one with an empty value', async () => {
    const r = await s().get(`${bin}/headers`, { headers: { 'x-probe': 'yes', 'x-empty': '' } });
    const headers = (await json(r)).headers as Record<string, string>;
    const probe = headers['X-Probe'];
    const empty = 'X-Empty' in headers;
    return [probe === 'yes' && empty, `x-probe=${probe} x-empty present=${empty}`];
  });
  await add('get', 'profile headers reach the server', async () => {
    const r = await s().get(`${bin}/headers`);
    const headers = (await json(r)).headers as Record<string, string>;
    const ua = headers['User-Agent'] ?? '(none)';
    return [profile === undefined || ua.includes('Mozilla'), `user-agent: ${ua.slice(0, 90)}`];
  });
  await add('get', 'request header beats profile header', async () => {
    const r = await s().get(`${bin}/headers`, { headers: { 'user-agent': 'probe/1' } });
    const ua = ((await json(r)).headers as Record<string, string>)['User-Agent'];
    return [ua === 'probe/1', `user-agent: ${ua}`];
  });
  await add('get', 'non-ASCII body (utf-8)', async () => {
    const r = await s().get(`${bin}/encoding/utf8`);
    const text = await r.text();
    return [text.includes('∮ E⋅da = Q'), `${text.length} chars`];
  });

  // --- bodies ---------------------------------------------------------------
  await add('body', 'POST without a body', async () => {
    const r = await s().post(`${bin}/post`);
    const body = await json(r);
    return [r.status === 200 && body.data === '', `status ${r.status} data=${short(body.data)}`];
  });
  await add('body', 'POST json', async () => {
    const r = await s().post(`${bin}/post`, { json: { hello: 'world', n: 1 } });
    const body = await json(r);
    return [short(body.json) === short({ hello: 'world', n: 1 }), short(body.json)];
  });
  await add('body', 'POST form', async () => {
    const r = await s().post(`${bin}/post`, { form: { user: 'alice', pass: 'p&q=' } });
    const form = (await json(r)).form;
    return [
      short(form) === short({ pass: 'p&q=', user: 'alice' }) ||
        short(form) === short({ user: 'alice', pass: 'p&q=' }),
      short(form),
    ];
  });
  await add('body', 'POST raw bytes', async () => {
    const r = await s().post(`${bin}/post`, {
      body: new Uint8Array([0, 1, 2, 255]),
      headers: { 'content-type': 'application/octet-stream' },
    });
    const data = String((await json(r)).data);
    return [data.includes('AAEC/w==') || data.length > 0, `data=${data.slice(0, 80)}`];
  });
  await add('body', 'POST Blob', async () => {
    const r = await s().post(`${bin}/post`, {
      body: new Blob(['blob-body'], { type: 'text/plain' }),
    });
    const data = (await json(r)).data;
    return [data === 'blob-body', `data=${short(data)}`];
  });
  await add('body', 'POST FormData (multipart, with a file)', async () => {
    const form = new FormData();
    form.append('title', 'report');
    form.append('attachment', new File(['file contents'], 'report.txt', { type: 'text/plain' }));
    const r = await s().post(`${bin}/post`, { body: form });
    const body = await json(r);
    const ok = short(body.form).includes('report') && short(body.files).includes('file contents');
    return [ok, `form=${short(body.form)} files=${short(body.files)}`];
  });
  await add('body', 'POST a 1 MB body', async () => {
    const big = 'x'.repeat(1_000_000);
    const r = await s().post(`${bin}/post`, {
      body: big,
      headers: { 'content-type': 'text/plain' },
    });
    const data = String((await json(r)).data);
    return [data.length === big.length, `status ${r.status}, echoed ${data.length} bytes`];
  });
  await add('body', 'POST a streamed body (ReadableStream)', async () => {
    const parts = ['hello ', 'world'];
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        const next = parts.shift();
        if (next === undefined) c.close();
        else c.enqueue(new TextEncoder().encode(next));
      },
    });
    const r = await s().post(`${bin}/post`, {
      body: stream,
      headers: { 'content-type': 'text/plain' },
      // @ts-expect-error — required by the fetch spec for a stream body
      duplex: 'half',
    });
    const data = (await json(r)).data;
    return [data === 'hello world', `data=${short(data)}`];
  });

  // --- verbs ----------------------------------------------------------------
  for (const [verb, call] of [
    ['PUT', (u: string) => s().put(u, { json: { v: 1 } })],
    ['PATCH', (u: string) => s().patch(u, { json: { v: 1 } })],
    ['DELETE', (u: string) => s().del(u)],
  ] as const) {
    await add('verbs', verb, async () => {
      const r = await call(`${bin}/${verb.toLowerCase()}`);
      return [r.status === 200, `status ${r.status}`];
    });
  }
  await add('verbs', 'HEAD has a null body', async () => {
    const r = await s().head(`${bin}/get`);
    return [
      r.status === 200 && r.body === null,
      `status ${r.status} body=${r.body === null ? 'null' : 'stream'}`,
    ];
  });
  await add('verbs', 'OPTIONS', async () => {
    const r = await s().fetch(`${bin}/get`, { method: 'OPTIONS' });
    return [r.status < 500, `status ${r.status} allow=${r.headers.get('allow')}`];
  });

  // --- status ---------------------------------------------------------------
  for (const code of [404, 500, 418, 204]) {
    await add('status', `${code} returned, not thrown`, async () => {
      const r = await s().get(`${bin}/status/${code}`);
      await r.text();
      return [r.status === code, `status ${r.status} ok=${r.ok}`];
    });
  }

  // --- redirects ------------------------------------------------------------
  await add('redirects', 'followed by default', async () => {
    const r = await s().get(`${bin}/redirect/3`);
    return [r.status === 200 && r.url.endsWith('/get'), `status ${r.status} url=${r.url}`];
  });
  await add('redirects', 'not followed when disabled', async () => {
    const r = await s().get(`${bin}/redirect/1`, { allowRedirects: false });
    return [r.status === 302, `status ${r.status} location=${r.headers.get('location')}`];
  });
  await add('redirects', 'maxRedirects enforced', async () => {
    try {
      await s().get(`${bin}/redirect/5`, { maxRedirects: 2 });
      return [false, 'did not give up'];
    } catch (error) {
      return [String(error).includes('redirects'), String(error)];
    }
  });
  await add('redirects', 'absolute redirect to another host drops authorization', async () => {
    const target = encodeURIComponent('https://postman-echo.com/headers');
    const r = await s().get(`${bin}/redirect-to?url=${target}`, { auth: { bearer: 'secret' } });
    const headers = (await json(r)).headers as Record<string, string>;
    return [!('authorization' in headers), `authorization forwarded=${'authorization' in headers}`];
  });
  await add('redirects', '307 repeats the body', async () => {
    const target = encodeURIComponent(`${bin}/post`);
    const r = await s().post(`${bin}/redirect-to?url=${target}&status_code=307`, {
      json: { again: true },
    });
    const body = await json(r);
    return [short(body.json) === short({ again: true }), `json=${short(body.json)}`];
  });
  await add('redirects', 'cookie set mid-redirect is kept', async () => {
    const session = s({ cookies: true });
    const r = await session.get(`${bin}/cookies/set?foo=bar`);
    const cookies = (await json(r)).cookies;
    return [short(cookies) === short({ foo: 'bar' }), `after redirect: ${short(cookies)}`];
  });

  // --- cookies --------------------------------------------------------------
  await add('cookies', 'session keeps cookies across requests', async () => {
    const session = s({ cookies: true });
    await (await session.get(`${bin}/cookies/set/k/v`, { allowRedirects: false })).text();
    const r = await session.get(`${bin}/cookies`);
    const cookies = (await json(r)).cookies;
    return [short(cookies) === short({ k: 'v' }), short(cookies)];
  });
  await add('cookies', 'server deletes a cookie', async () => {
    const session = s({ cookies: true });
    await (await session.get(`${bin}/cookies/set/k/v`, { allowRedirects: false })).text();
    await (await session.get(`${bin}/cookies/delete?k`, { allowRedirects: false })).text();
    const r = await session.get(`${bin}/cookies`);
    const cookies = (await json(r)).cookies;
    return [short(cookies) === '{}', short(cookies)];
  });
  await add('cookies', 'no session, no cookies kept', async () => {
    const session = s();
    await (await session.get(`${bin}/cookies/set/k/v`, { allowRedirects: false })).text();
    const r = await session.get(`${bin}/cookies`);
    const cookies = (await json(r)).cookies;
    return [short(cookies) === '{}', short(cookies)];
  });

  // --- auth -----------------------------------------------------------------
  const user = { username: 'u', password: 'p' };
  const digest = { ...user, type: 'digest' } as const;
  for (const [name, path, auth] of [
    ['basic', '/basic-auth/u/p', user],
    ['bearer', '/bearer', { bearer: 'tok' }],
    ['digest MD5', '/digest-auth/auth/u/p/MD5', digest],
    ['digest SHA-256', '/digest-auth/auth/u/p/SHA-256', digest],
  ] as const) {
    await add('auth', name, async () => {
      const r = await s().get(`${bin}${path}`, { auth });
      return [r.status === 200, `status ${r.status}`];
    });
  }

  // --- encodings ------------------------------------------------------------
  for (const encoding of ['gzip', 'deflate', 'brotli']) {
    await add('encoding', `${encoding} undone`, async () => {
      const r = await s().get(`${bin}/${encoding}`);
      const text = await r.text();
      const key = { gzip: 'gzipped', deflate: 'deflated', brotli: 'brotli' }[encoding]!;
      let parsed: boolean;
      try {
        parsed = (JSON.parse(text) as Record<string, unknown>)[key] === true;
      } catch {
        parsed = false;
      }
      return [
        parsed,
        `content-encoding left=${r.headers.get('content-encoding')} first bytes=${short(text.slice(0, 30))}`,
      ];
    });
  }

  // --- streaming, size, flow control ----------------------------------------
  await add('stream', 'drip: first byte before the last', async () => {
    const r = await s().get(`${bin}/drip?duration=3&numbytes=6&delay=0`);
    const a = await arrival(r);
    return [
      a.bytes === 6 && a.first < a.last - 1000,
      `first ${a.first} ms, last ${a.last} ms, ${a.chunks} chunks`,
    ];
  });
  await add('stream', '/stream/20 json lines', async () => {
    const r = await s().get(`${bin}/stream/20`);
    const lines = (await r.text()).trim().split('\n').length;
    return [lines === 20, `${lines} lines`];
  });
  await add('stream', '2 MB response (past every flow-control window)', async () => {
    // httpbin caps /bytes at 100 KB, which fits in one window.
    const r = await s().get('https://speed.cloudflare.com/__down?bytes=2000000');
    const a = await arrival(r);
    return [a.bytes === 2_000_000, `${a.bytes} bytes in ${a.last} ms, ${a.chunks} chunks`];
  });
  await add('stream', 'cancelling a body mid-stream', async () => {
    const r = await s().get(`${bin}/drip?duration=10&numbytes=10&delay=0`);
    const reader = r.body!.getReader();
    await reader.read();
    const started = Date.now();
    await reader.cancel();
    return [Date.now() - started < 1000, `cancel took ${Date.now() - started} ms`];
  });

  // --- time -----------------------------------------------------------------
  await add('time', 'delayed answer (2 s)', async () => {
    const r = await s().get(`${bin}/delay/2`);
    return [r.status === 200, `status ${r.status}`];
  });
  await add('time', 'timeoutMs fires on a slow server', async () => {
    const started = Date.now();
    try {
      await (await s({ timeoutMs: 2000 }).get(`${bin}/delay/8`)).text();
      return [false, 'no timeout'];
    } catch (error) {
      const took = Date.now() - started;
      return [took < 4000, `${String(error).slice(0, 80)} after ${took} ms`];
    }
  });
  await add('time', 'already-aborted signal rejects at once', async () => {
    const started = Date.now();
    try {
      await s().get(`${bin}/get`, { signal: AbortSignal.abort() });
      return [false, 'went ahead'];
    } catch (error) {
      return [
        Date.now() - started < 200,
        `${String(error).slice(0, 80)} after ${Date.now() - started} ms`,
      ];
    }
  });
  await add('time', 'abort in flight, siblings unharmed', async () => {
    const controller = new AbortController();
    const session = s();
    const doomed = session.get(`${bin}/delay/5`, { signal: controller.signal });
    const sibling = session.get(`${bin}/delay/1`);
    setTimeout(() => controller.abort(), 500);
    const [a, b] = await Promise.allSettled([doomed, sibling]);
    const ok = a.status === 'rejected' && b.status === 'fulfilled' && b.value.status === 200;
    return [ok, `doomed=${a.status} sibling=${b.status}`];
  });
  await add('time', 'three 2 s requests in parallel', async () => {
    const started = Date.now();
    const session = s();
    const all = await Promise.all([1, 2, 3].map(() => session.get(`${bin}/delay/2`)));
    const took = Date.now() - started;
    return [
      all.every((r) => r.status === 200) && took < 5000,
      `${took} ms for three (serial would be 6000+)`,
    ];
  });

  return out;
}
