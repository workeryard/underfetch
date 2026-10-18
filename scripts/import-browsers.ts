// Writes src/fingerprint/browsers.ts from curl-impersonate's captures of real browsers,
// and from our own in captures/ (see scripts/from-frames.ts) for browsers newer
// than any it has.
//
// Each capture is a ClientHello and an HTTP/2 opening taken from the browser
// itself, which is the same data impers and curl_cffi are tested against. The
// expected fingerprints are computed here from the capture, so the test that
// compares them with what we send is comparing against the browser, not
// against ourselves.
//
//   pnpm import:browsers            # the pinned commit
//   pnpm import:browsers <sha>      # another one
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { GREASE } from '../src/fingerprint/grease';
import { akamai, ja4 } from '../src/fingerprint/verify';
import type { Capture } from '../src/fingerprint/capture';

const REPO = 'lexiforest/curl-impersonate';
const PINNED = '5bfbe06a949723b20c369384a40755668371bbe1';
const commit = process.argv[2] ?? PINNED;

const EXTENSIONS: Record<string, number> = {
  server_name: 0x0000,
  status_request: 0x0005,
  supported_groups: 0x000a,
  ec_point_formats: 0x000b,
  signature_algorithms: 0x000d,
  application_layer_protocol_negotiation: 0x0010,
  signed_certificate_timestamp: 0x0012,
  padding: 0x0015,
  extended_master_secret: 0x0017,
  compress_certificate: 0x001b,
  record_size_limit: 0x001c,
  delegated_credentials: 0x0022,
  session_ticket: 0x0023,
  pre_shared_key: 0x0029,
  supported_versions: 0x002b,
  psk_key_exchange_modes: 0x002d,
  keyshare: 0x0033,
  application_settings: 0x4469,
  application_settings_new: 0x44cd,
  encrypted_client_hello: 0xfe0d,
  renegotiation_info: 0xff01,
};

/** Extensions the TLS module cannot send yet; a capture needing one is skipped. */
const UNSUPPORTED: Record<number, string> = {};

interface RawExtension {
  type: string;
  alps_alpn_list?: string[];
  alpn_list?: string[];
  sig_hash_algs?: number[];
  supported_groups?: (number | string)[];
  key_shares?: { group: number | string; length?: number }[];
  record_size_limit?: number;
}

interface RawFrame {
  frame_type: string;
  settings?: { key: number; value: number }[];
  window_size_increment?: number;
  stream_id: number;
  headers?: string[];
  pseudo_headers?: string[];
}

interface RawSignature {
  browser: { name: string; version: string };
  signature: {
    tls_client_hello: { ciphersuites: (number | string)[]; extensions: RawExtension[] };
    http2: { frames: RawFrame[] };
  };
}

const raw = (path: string) => `https://raw.githubusercontent.com/${REPO}/${commit}/${path}`;

async function text(url: string): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: ${response.status}`);
  return response.text();
}

/** X25519MLKEM768 and X25519Kyber768Draft00, which the TLS module cannot make. */
// X25519Kyber768Draft00, which Chrome 124 to 130 offered. It predates ML-KEM
// as standardised and nothing here can make it. X25519MLKEM768 (0x11ec) can
// be made now, so it stays.
const UNMAKEABLE = [0x6399];

const grease = (value: number | string) => (value === 'GREASE' ? GREASE[0] : Number(value));

/**
 * The priority each family puts on its HEADERS frame. The captures do not
 * record it; these are curl-impersonate's, from lib/impersonate.c. Safari
 * sends none.
 */
const PRIORITY: Record<string, { weight: number; exclusive: boolean } | undefined> = {
  chrome: { weight: 256, exclusive: true },
  edge: { weight: 256, exclusive: true },
  firefox: { weight: 42, exclusive: false },
  tor: { weight: 42, exclusive: false },
};

/** Chrome began shuffling its extensions in 110, and every Chromium with it. */
function shuffles(browser: string, version: string): boolean {
  return (browser === 'chrome' || browser === 'edge') && Number.parseInt(version, 10) >= 110;
}

/** HTTP/2 settings and window update, from curl-impersonate's own target table. */
interface Declared {
  settings: [number, number][];
  windowUpdate: number;
}

/**
 * The older captures recorded only the HEADERS frame, not the SETTINGS or the
 * window update before it. For those, the values come from the table
 * curl-impersonate itself sends them from, lib/impersonate.c in its patch.
 */
function declaredHttp2(patch: string): Map<string, Declared> {
  const source = patch
    .slice(patch.indexOf('+++ b/lib/impersonate.c'), patch.indexOf('+++ b/lib/impersonate.h'))
    .split('\n')
    .filter((line) => line.startsWith('+'))
    .map((line) => line.slice(1))
    .join('\n');
  const out = new Map<string, Declared>();
  for (const block of source.split(/\n {2}\{\n/)) {
    const target = /\.target = "([^"]+)"/.exec(block)?.[1];
    const settings = /\.http2_settings = "([^"]+)"/.exec(block)?.[1];
    const window = /\.http2_window_update = (\d+)/.exec(block)?.[1];
    if (target === undefined || settings === undefined) continue;
    out.set(target, {
      settings: settings.split(';').map((pair) => {
        const [id, value] = pair.split(':').map(Number);
        return [id!, value!];
      }),
      windowUpdate: Number(window ?? 0),
    });
  }
  return out;
}

async function convert(
  file: string,
  sig: RawSignature,
  declared: Declared | undefined,
): Promise<Capture | string> {
  const hello = sig.signature.tls_client_hello;
  const kept = hello.extensions.filter((e) => e.type !== 'pre_shared_key');
  // A pre_shared_key only appears when a session is resumed, which a fresh
  // connection never is; the capture happened to be taken on a second visit.
  let greaseSeen = 0;
  const extensions = kept.map((e) => {
    if (e.type === 'GREASE') return GREASE[greaseSeen++]!;
    const code = EXTENSIONS[e.type];
    if (code === undefined) throw new Error(`${file}: unknown extension ${e.type}`);
    return code;
  });
  const missing = extensions.find((code) => UNSUPPORTED[code] !== undefined);
  if (missing !== undefined) return `needs ${UNSUPPORTED[missing]}`;

  const find = (type: string) => kept.find((e) => e.type === type);
  const alpsExt = find('application_settings') ?? find('application_settings_new');
  const groups = find('supported_groups')?.supported_groups ?? [];
  const shares = (find('keyshare')?.key_shares ?? []).map((share) => grease(share.group));

  const frames = sig.signature.http2.frames;
  const settings = frames.find((f) => f.frame_type === 'SETTINGS')?.settings ?? [];
  const window = frames.find((f) => f.frame_type === 'WINDOW_UPDATE' && f.stream_id === 0);
  const headersFrame = frames.find((f) => f.frame_type === 'HEADERS');
  if (headersFrame === undefined) throw new Error(`${file}: no HEADERS frame`);
  const http2 = {
    settings:
      settings.length > 0
        ? settings.map(({ key, value }) => [key, value] as [number, number])
        : (declared?.settings ?? []),
    windowUpdate: window?.window_size_increment ?? declared?.windowUpdate ?? 0,
    pseudoHeaderOrder: (headersFrame.pseudo_headers ?? []).map(
      (name) => name.slice(1, 2) as 'm' | 'a' | 's' | 'p',
    ),
    priority: PRIORITY[sig.browser.name],
  };
  const headers = (headersFrame.headers ?? []).map((line): [string, string] => {
    const colon = line.indexOf(':');
    const name = line.slice(0, colon).trim().toLowerCase();
    // `accept-encoding` is kept as the browser sent it; what the runtime
    // cannot decode is cut from it when a session is made, not here.
    return [name, line.slice(colon + 1).trim()];
  });

  if (http2.settings.length === 0) throw new Error(`${file}: no HTTP/2 settings anywhere`);

  const alpn = find('application_layer_protocol_negotiation')?.alpn_list ?? [];
  const ciphers = hello.ciphersuites.map(grease);
  const signatureSchemes = find('signature_algorithms')?.sig_hash_algs ?? [];
  const browser = sig.browser.name;
  return {
    source: file,
    ciphers,
    signatureSchemes,
    greaseNamedGroup: groups[0] === 'GREASE',
    // Never a group we cannot make: advertised without a key share, it invites
    // a HelloRetryRequest for it, and nearly every server prefers the
    // post-quantum ones, so offering one fails the handshake.
    namedGroups: groups.map(grease).filter((group) => !UNMAKEABLE.includes(group)),
    // Which groups the browser sent a key share for. Firefox sends P-256
    // beside the other two, which the TLS module then sends and answers too.
    keyShares: shares.filter((group) => !UNMAKEABLE.includes(group)),
    extensions,
    shuffled: shuffles(browser, sig.browser.version),
    alpn,
    alps: alpsExt?.alps_alpn_list,
    // The captures do not record it; these are the sizes each family sends.
    echPayload: find('encrypted_client_hello')
      ? browser === 'firefox' || browser === 'tor'
        ? 223
        : 176
      : undefined,
    delegatedCredentials: find('delegated_credentials')?.sig_hash_algs,
    recordSizeLimit: find('record_size_limit')?.record_size_limit,
    http2,
    headers,
    expected: {
      ja4: await ja4({
        ciphers,
        extensions,
        signatureSchemes,
        alpn,
        hasServerName: extensions.includes(0x0000),
      }),
      akamai: akamai(http2),
    },
  };
}

const tree = (await (
  await fetch(`https://api.github.com/repos/${REPO}/git/trees/${commit}?recursive=1`)
).json()) as { tree: { path: string }[] };
const files = tree.tree
  .map((entry) => entry.path)
  .filter((path) => path.startsWith('tests/signatures/') && path.endsWith('.yaml'))
  .map((path) => path.slice('tests/signatures/'.length, -'.yaml'.length));

// targets.yaml pairs each wrapper with the capture it is tested against. Its
// names carry the OS the capture was taken on, which not every file name does,
// so a target falls back to the file for the same browser and version.
const targets = (
  parse(await text(raw('tests/targets.yaml'))) as [string, unknown, unknown, string][]
)
  .map(([wrapper, env, , capture]) => {
    // Most targets have a wrapper script; a few appear only as the
    // libcurl-impersonate test, named by its CURL_IMPERSONATE variable.
    const named = (env as { CURL_IMPERSONATE?: string } | null)?.CURL_IMPERSONATE;
    const name = wrapper.startsWith('curl_') ? wrapper.slice('curl_'.length) : named;
    return [name, capture] as const;
  })
  .filter((entry): entry is readonly [string, string] => entry[0] !== undefined)
  .filter(([name], i, all) => all.findIndex(([other]) => other === name) === i);

const declared = declaredHttp2(await text(raw('patches/curl.patch')));

const out: Record<string, Capture> = {};
for (const [name, wanted] of targets) {
  const [browser, version] = wanted.split('_');
  const file = files.includes(wanted)
    ? wanted
    : files.find((f) => f.startsWith(`${browser}_${version}_`) || f === `${browser}_${version}`);
  if (file === undefined) {
    console.log(`skip ${name}: no capture named ${wanted}`);
    continue;
  }
  const sig = parse(await text(raw(`tests/signatures/${file}.yaml`))) as RawSignature;
  const capture = await convert(file, sig, declared.get(name));
  if (typeof capture === 'string') {
    console.log(`skip ${name}: ${capture}`);
    continue;
  }
  out[name] = capture;
  console.log(`ok   ${name.padEnd(18)} ${capture.expected.ja4}  ${file}`);
}

// Our own captures, recorded from the browser by scripts/capture-frames.ts.
// What we send is checked against the fingerprint worked out here, from the
// recording, exactly as for curl-impersonate's.
const own = fileURLToPath(new URL('../captures/', import.meta.url));
for (const file of readdirSync(own)
  .filter((f) => f.endsWith('.json'))
  .sort()) {
  const { name, capture } = JSON.parse(readFileSync(`${own}${file}`, 'utf8')) as {
    name: string;
    capture: Omit<Capture, 'expected'>;
  };
  const expected = {
    ja4: await ja4({
      ciphers: [...capture.ciphers],
      extensions: [...capture.extensions],
      signatureSchemes: [...capture.signatureSchemes],
      alpn: [...capture.alpn],
      hasServerName: capture.extensions.includes(0x0000),
    }),
    akamai: akamai(capture.http2),
  };
  out[name] = { ...capture, expected };
  console.log(`ok   ${name.padEnd(18)} ${expected.ja4}  captures/${file}`);
}

const body = `// Generated by scripts/import-browsers.ts from ${REPO}@${commit.slice(0, 7)}
// and from captures/.
// Do not edit: import again instead.

import type { Capture } from './capture';

export const captures = ${JSON.stringify(out, null, 2)} as const satisfies Record<string, Capture>;
`;
writeFileSync(fileURLToPath(new URL('../src/fingerprint/browsers.ts', import.meta.url)), body);
console.log(`\nwrote ${Object.keys(out).length} browsers to src/fingerprint/browsers.ts`);
