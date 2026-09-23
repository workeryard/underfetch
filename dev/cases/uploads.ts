/**
 * Uploads sent as they arrive, never read whole into memory: chunked over
 * HTTP/1.1, frame by frame over HTTP/2. A `ReadableStream` body is what asks
 * for it.
 */

import { Session, type WorkerSessionDefaults } from '../../src/workers/index';
import { run, type Check, type Outcome } from './probe';

export async function uploadCases(bin: string, profile: WorkerSessionDefaults['impersonate']) {
  const s = () => new Session({ timeoutMs: 60_000, retry: false, impersonate: profile });
  const out: Outcome[] = [];
  const add = async (group: string, name: string, check: Check) =>
    out.push(await run(group, name, check));

  await add('uploads', 'a 5 MB upload streamed, never held whole', async () => {
    let left = 5_000_000;
    const chunk = new Uint8Array(64 * 1024).fill(0x61);
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (left <= 0) return c.close();
        const piece = chunk.subarray(0, Math.min(chunk.length, left));
        left -= piece.length;
        c.enqueue(piece);
      },
    });
    const started = Date.now();
    const r = await s().post('https://speed.cloudflare.com/__up', {
      body: stream,
      headers: { 'content-type': 'application/octet-stream' },
    });
    await r.text();
    return [r.status === 200 && left <= 0, `status ${r.status} in ${Date.now() - started} ms`];
  });

  await add('uploads', 'plain http:// upload sent in chunks', async () => {
    const parts = ['streamed ', 'over ', 'HTTP/1.1'];
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        const next = parts.shift();
        if (next === undefined) c.close();
        else c.enqueue(new TextEncoder().encode(next));
      },
    });
    const r = await s().post(`${bin.replace('https:', 'http:')}/post`, {
      body,
      headers: { 'content-type': 'text/plain' },
    });
    const echoed = (await r.json()) as { data?: string; headers?: Record<string, string> };
    const framing = echoed.headers?.['Transfer-Encoding'] ?? 'none';
    return [
      echoed.data === 'streamed over HTTP/1.1',
      `data=${JSON.stringify(echoed.data)} transfer-encoding=${framing}`,
    ];
  });
  return out;
}
