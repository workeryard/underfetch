/**
 * What every live case shares: a limit on how long one may take, and a
 * result that records a failure instead of ending the run.
 */

export interface Outcome {
  group: string;
  name: string;
  ok: boolean;
  ms: number;
  detail: string;
  /** Outside the page asked for; not run. */
  skipped?: boolean;
}

export type Check = () => Promise<[ok: boolean, detail: string]>;

const CASE_LIMIT_MS = 30_000;

/**
 * Which cases this invocation runs, by their position in the run. A deployed
 * Worker may open only so many connections per invocation, so a long run is
 * asked for a page at a time. Module state, which is fine for a probe asked
 * one request at a time; `page` resets it for each.
 */
let window = { from: 0, count: Infinity, seen: 0 };

export function page(from: number, count: number): void {
  window = { from, count, seen: 0 };
}

/** How many cases the run came across, inside the page or not. */
export function seen(): number {
  return window.seen;
}

export async function run(group: string, name: string, check: Check): Promise<Outcome> {
  const at = window.seen++;
  if (at < window.from || at >= window.from + window.count) {
    return { group, name, ok: true, ms: 0, detail: '', skipped: true };
  }
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const limit = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`no answer in ${CASE_LIMIT_MS} ms`)),
        CASE_LIMIT_MS,
      );
    });
    const [ok, detail] = await Promise.race([check(), limit]);
    return { group, name, ok, ms: Date.now() - started, detail };
  } catch (error) {
    const cause =
      error instanceof Error && error.cause instanceof Error
        ? ` (cause: ${error.cause.message})`
        : '';
    return {
      group,
      name,
      ok: false,
      ms: Date.now() - started,
      detail: `threw ${String(error)}${cause}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export const json = async (response: Response) =>
  (await response.json()) as Record<string, unknown>;
export const short = (value: unknown) => JSON.stringify(value).slice(0, 240);

/** Reads a body and reports when the first chunk and the last arrived. */
export async function arrival(response: Response) {
  const started = Date.now();
  const reader = response.body!.getReader();
  let first = -1;
  let chunks = 0;
  let bytes = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (first < 0) first = Date.now() - started;
    chunks++;
    bytes += value.byteLength;
  }
  return { first, last: Date.now() - started, chunks, bytes };
}

export function websocketKey(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
}
