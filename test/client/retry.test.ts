import { describe, expect, it } from 'vitest';
import { withRetry } from '../../src/client/retry';

/**
 * A sender that answers from a script and records what it was asked. Each
 * entry builds a fresh answer: handing out clones of one Response hangs, since
 * cancelling a branch of a tee leaves the others waiting on a source nobody
 * reads.
 */
function sender(script: (() => Response | Error)[]) {
  const seen: { method: string; body: string }[] = [];
  let next = 0;
  const send = async (request: Request) => {
    seen.push({ method: request.method, body: await request.text() });
    const answer = script[Math.min(next++, script.length - 1)]!();
    if (answer instanceof Error) throw answer;
    return answer;
  };
  return { send, seen, calls: () => seen.length };
}

const status =
  (code: number, headers: Record<string, string> = {}) =>
  () =>
    new Response('body', { status: code, headers });

const fails = (message: string) => () => new TypeError(message);

/** Real timers, kept short: a fake clock and an async retry loop interleave badly. */
const quick = { maxDelayMs: 10 } as const;

describe('retry', () => {
  it('repeats a 503 and returns the answer that worked', async () => {
    const server = sender([status(503), status(503), status(200)]);
    const response = await withRetry(new Request('https://e.com/'), server.send, quick);

    expect(response.status).toBe(200);
    expect(server.calls()).toBe(3);
  });

  it('gives up and hands back the last failure', async () => {
    const server = sender([status(500)]);
    const response = await withRetry(new Request('https://e.com/'), server.send, {
      ...quick,
      limit: 2,
    });

    expect(response.status).toBe(500);
    // The first attempt plus two more.
    expect(server.calls()).toBe(3);
  });

  it('leaves a POST alone, because repeating it may do the thing twice', async () => {
    const server = sender([status(503)]);
    const response = await withRetry(
      new Request('https://e.com/', { method: 'POST', body: 'x' }),
      server.send,
    );

    expect(response.status).toBe(503);
    expect(server.calls()).toBe(1);
  });

  it('repeats a POST when the caller says it is safe', async () => {
    const server = sender([status(503), status(200)]);
    await withRetry(
      new Request('https://e.com/', { method: 'POST', body: 'payload' }),
      server.send,
      {
        ...quick,
        methods: ['POST'],
      },
    );

    expect(server.calls()).toBe(2);
    // The body survives the first attempt, which consumed the stream.
    expect(server.seen.map((call) => call.body)).toEqual(['payload', 'payload']);
  });

  it('retries a thrown transport error', async () => {
    const server = sender([fails('connection refused'), status(200)]);
    const response = await withRetry(new Request('https://e.com/'), server.send, quick);
    expect(response.status).toBe(200);
  });

  it('rethrows when every attempt threw', async () => {
    const server = sender([fails('connection refused')]);
    await expect(
      withRetry(new Request('https://e.com/'), server.send, { ...quick, limit: 1 }),
    ).rejects.toThrow(/connection refused/);
  });

  it('does not retry an abort, which is the caller changing their mind', async () => {
    const server = sender([
      () => {
        const aborted = new Error('cancelled');
        aborted.name = 'AbortError';
        return aborted;
      },
    ]);

    await expect(withRetry(new Request('https://e.com/'), server.send)).rejects.toThrow(
      /cancelled/,
    );
    expect(server.calls()).toBe(1);
  });

  it('waits as long as the server asked, not as long as backoff would', async () => {
    // 60ms is far longer than the few milliseconds backoff would pick first.
    const server = sender([status(429, { 'retry-after': '0.06' }), status(200)]);
    const started = Date.now();
    await withRetry(new Request('https://e.com/'), server.send, { maxDelayMs: 1_000 });

    expect(server.calls()).toBe(2);
    expect(Date.now() - started).toBeGreaterThanOrEqual(40);
  });

  it('still caps a Retry-After it considers unreasonable', async () => {
    // A server asking for an hour does not get to hold the request open.
    const server = sender([status(503, { 'retry-after': '3600' }), status(200)]);
    const started = Date.now();
    await withRetry(new Request('https://e.com/'), server.send, { maxDelayMs: 20 });

    expect(server.calls()).toBe(2);
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('turns off completely when told to', async () => {
    const server = sender([status(503)]);
    await withRetry(new Request('https://e.com/'), server.send, false);
    expect(server.calls()).toBe(1);

    const other = sender([status(503)]);
    await withRetry(new Request('https://e.com/'), other.send, 0);
    expect(other.calls()).toBe(1);
  });

  it('passes a status it was not told to retry straight through', async () => {
    const server = sender([status(404)]);
    expect((await withRetry(new Request('https://e.com/'), server.send)).status).toBe(404);
    expect(server.calls()).toBe(1);
  });
});
