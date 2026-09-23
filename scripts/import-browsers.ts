// Writes src/browsers.ts from curl-impersonate's captures of real browsers.
//
// Each capture is a ClientHello and an HTTP/2 opening taken from the browser
// itself, which is the same data impers and curl_cffi are tested against. The
// expected fingerprints are computed here from the capture, so the test that
// compares them with what we send is comparing against the browser, not
// against ourselves.
//
//   pnpm import:browsers            # the pinned commit
//   pnpm import:browsers <sha>      # another one
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { GREASE } from '../src/grease';
import { akamai, ja4 } from '../src/verify';
import type { Capture } from '../src/capture';

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
const UNSUPPORTED: Record<number, string> = {
  0x0015: 'padding, whose length depends on the finished ClientHello',
};

interface RawExtension {
  type: string;
  alps_alpn_list?: string[];
  alpn_list?: string[];
  sig_hash_algs?: number[];
  supported_groups?: (number | string)[];
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

const grease = (value: number | string) => (value === 'GREASE' ? GREASE[0] : Number(value));

/** Chrome began shuffling its extensions in 110, and every Chromium with it. */
function shuffles(browser: string, version: string): boolean {
  return (browser === 'chrome' || browser === 'edge') && Number.parseInt(version, 10) >= 110;
}

async function convert(file: string, sig: RawSignature): Promise<Capture | string> {
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

  const frames = sig.signature.http2.frames;
  const settings = frames.find((f) => f.frame_type === 'SETTINGS')?.settings ?? [];
  const window = frames.find((f) => f.frame_type === 'WINDOW_UPDATE' && f.stream_id === 0);
  const headersFrame = frames.find((f) => f.frame_type === 'HEADERS');
  if (headersFrame === undefined) throw new Error(`${file}: no HEADERS frame`);
  const http2 = {
    settings: settings.map(({ key, value }) => [key, value] as [number, number]),
    windowUpdate: window?.window_size_increment ?? 0,
    pseudoHeaderOrder: (headersFrame.pseudo_headers ?? []).map(
      (name) => name.slice(1, 2) as 'm' | 'a' | 's' | 'p',
    ),
  };
  const headers = (headersFrame.headers ?? []).map((line): [string, string] => {
    const colon = line.indexOf(':');
    const name = line.slice(0, colon).trim().toLowerCase();
    // DecompressionStream undoes gzip and deflate only; offering brotli or
    // zstd would invite answers we cannot read.
    const value = name === 'accept-encoding' ? 'gzip, deflate' : line.slice(colon + 1).trim();
    return [name, value];
  });

  const alpn = find('application_layer_protocol_negotiation')?.alpn_list ?? [];
  const ciphers = hello.ciphersuites.map(grease);
  const signatureSchemes = find('signature_algorithms')?.sig_hash_algs ?? [];
  const browser = sig.browser.name;
  return {
    source: file,
    ciphers,
    signatureSchemes,
    greaseNamedGroup: groups[0] === 'GREASE',
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
  .filter(([wrapper]) => wrapper.startsWith('curl_'))
  .map(([wrapper, , , capture]) => [wrapper.slice('curl_'.length), capture] as const);

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
  const capture = await convert(file, sig);
  if (typeof capture === 'string') {
    console.log(`skip ${name}: ${capture}`);
    continue;
  }
  out[name] = capture;
  console.log(`ok   ${name.padEnd(18)} ${capture.expected.ja4}  ${file}`);
}

const body = `// Generated by scripts/import-browsers.ts from ${REPO}@${commit.slice(0, 7)}.
// Do not edit: import again instead.

import type { Capture } from './capture';

export const captures = ${JSON.stringify(out, null, 2)} as const satisfies Record<string, Capture>;
`;
writeFileSync(fileURLToPath(new URL('../src/browsers.ts', import.meta.url)), body);
console.log(`\nwrote ${Object.keys(out).length} browsers to src/browsers.ts`);
