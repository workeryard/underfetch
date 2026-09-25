// Asks the running dev worker (`make dev`) and prints what it answered, short.
//
//   tsx scripts/live.ts fingerprints [--as chrome]
//   tsx scripts/live.ts cases [--as chrome] [--only http,tls]
//   tsx scripts/live.ts resume --as chrome
//   tsx scripts/live.ts state-save --as chrome   then restart the server, and
//   tsx scripts/live.ts state-load
//   tsx scripts/live.ts fetch --url https://httpbin.org/ip [--as chrome] [--proxy socks5://h:1080]
//
// PROBE_URL and PROBE_TOKEN point it at a deployed worker instead.
//
// Exits non-zero when something failed, so make stops on it.

const [command, ...rest] = process.argv.slice(2);
const flags = new Map<string, string>();
for (let i = 0; i < rest.length; i += 2) flags.set(rest[i]!.replace(/^--/, ''), rest[i + 1] ?? '');
const port = flags.get('port') ?? process.env.PORT ?? '8799';
// A deployed worker instead of the local one, with the token it demands.
const base = process.env.PROBE_URL ?? `http://localhost:${port}`;
const token = process.env.PROBE_TOKEN;

async function ask(
  path: string,
  params: Record<string, string | undefined> = {},
): Promise<unknown> {
  const url = new URL(path, base);
  for (const [name, value] of Object.entries(params)) {
    if (value) url.searchParams.set(name, value);
  }
  const response = await fetch(url, token ? { headers: { 'x-probe-token': token } } : {}).catch(
    () => {
      throw new Error(`nothing answers at ${base}; start it with \`make dev\``);
    },
  );
  const text = await response.text();
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${path} answered ${response.status}: ${text.slice(0, 300)}`);
  }
}

interface Verdict {
  name: string;
  error?: string;
  ja4?: { ok: boolean; seen: string; want: string };
  akamai?: { ok: boolean };
}
interface Outcome {
  group: string;
  name: string;
  ok: boolean;
  detail: string;
}

let failed = false;
const as = flags.get('as');

switch (command) {
  case 'fingerprints': {
    const { results } = (await ask('/', { as })) as { results: Verdict[] };
    for (const r of results) {
      const ok = r.ja4?.ok === true && r.akamai?.ok === true;
      failed ||= !ok;
      const why = r.error ?? (r.ja4?.ok ? 'akamai differs' : `ja4 ${r.ja4?.seen} ≠ ${r.ja4?.want}`);
      console.log(`${ok ? 'ok  ' : 'FAIL'} ${r.name}${ok ? '' : `  ${why}`}`);
    }
    console.log(
      `${results.filter((r) => r.ja4?.ok && r.akamai?.ok).length} of ${results.length} match`,
    );
    break;
  }
  case 'cases': {
    // A deployed Worker may open only so many connections per invocation, so
    // there the run is asked for a few cases at a time.
    const step = Number(flags.get('page') ?? (process.env.PROBE_URL ? 4 : Infinity));
    const results: Outcome[] = [];
    for (let from = 0; ; from += step) {
      const out = (await ask('/cases', {
        as,
        only: flags.get('only'),
        from: String(from),
        count: String(step),
      })) as { cases: number; results: Outcome[] };
      results.push(...out.results);
      if (from + step >= out.cases) break;
    }
    for (const r of results.filter((r) => !r.ok)) {
      console.log(`FAIL ${r.group}/${r.name}  ${r.detail.slice(0, 160)}`);
    }
    const passed = results.filter((r) => r.ok).length;
    console.log(`${as ?? 'no profile'}: ${passed} of ${results.length} passed`);
    failed = passed !== results.length;
    break;
  }
  case 'resume': {
    const { hellos } = (await ask('/resume', { as })) as {
      hellos: { ja4: string; psk: boolean }[];
    };
    hellos.forEach((h, i) =>
      console.log(`request ${i + 1}  ${h.ja4}  ${h.psk ? 'resumed' : 'full handshake'}`),
    );
    failed = !hellos.slice(1).every((h) => h.psk);
    break;
  }
  case 'state-save': {
    const { bytes } = (await ask('/state/save', { as })) as { bytes: number };
    console.log(`saved ${bytes} bytes to the dev KV; restart the server, then state-load`);
    break;
  }
  case 'state-load': {
    const out = (await ask('/state/load')) as { ja4: string; resumed: boolean; cookies: unknown };
    console.log(`first request  ${out.ja4}  ${out.resumed ? 'resumed' : 'full handshake'}`);
    console.log(`cookies        ${JSON.stringify(out.cookies)}`);
    failed = !out.resumed;
    break;
  }
  case 'fetch': {
    const out = (await ask('/fetch', {
      url: flags.get('url'),
      as,
      proxy: flags.get('proxy'),
      max: flags.get('max'),
      resource: flags.get('resource'),
    })) as { status: number; elapsedMs: number; body: string };
    console.log(`${out.status} in ${out.elapsedMs} ms`);
    console.log(out.body);
    failed = out.status >= 400;
    break;
  }
  default:
    console.error(
      'usage: live.ts fingerprints|cases|resume|state-save|state-load|fetch [--as name]',
    );
    failed = true;
}
process.exit(failed ? 1 : 0);
