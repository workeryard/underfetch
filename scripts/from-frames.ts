// Turns what scripts/capture-frames.ts recorded of a real browser into a
// capture in captures/, which scripts/import-browsers.ts then reads beside
// curl-impersonate's — for a browser newer than any it has.
//
//   pnpm tsx scripts/from-frames.ts frames.json firefox158 firefox_158.0_win11
//
// The ClientHello is the first one recorded from a browser, and the headers
// those of its first navigation, so record with nothing else connecting.
// Anything the TLS module would send differently from what the browser did is
// reported rather than smoothed over.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { GREASE } from '../src/fingerprint/grease';
import type { Capture } from '../src/fingerprint/capture';
import { BUILT_BY_TLS } from '../src/fingerprint/extensions';

const [input, name, source] = process.argv.slice(2);
if (!input || !name || !source) {
  console.error('usage: from-frames.ts <frames.json> <name> <source>');
  process.exit(1);
}

interface Logged {
  type: string;
  connection: number;
  bytes?: string;
  ja4?: string;
  settings?: [number, number][];
  increment?: number;
  stream: number;
  path?: string;
  exclusive?: boolean;
  weight?: number;
  priorityFlag?: boolean;
  headers?: [string, string][];
}
const log = JSON.parse(readFileSync(input, 'utf8')) as Logged[];

const navigation = log.find(
  (e) =>
    e.type === 'HEADERS' &&
    e.path === '/' &&
    e.headers?.some(([n, v]) => n === 'user-agent' && v.startsWith('Mozilla/')),
);
if (navigation === undefined) throw new Error('no navigation from a browser was recorded');
const helloEntry = log.find((e) => e.type === 'CLIENT_HELLO' && e.bytes !== undefined);
if (helloEntry === undefined) throw new Error('no ClientHello was recorded');
const record = Buffer.from(helloEntry.bytes!, 'hex');
const opening = log.filter((e) => e.connection === navigation.connection);
const settings = opening.find((e) => e.type === 'SETTINGS')?.settings ?? [];
const windowUpdate = opening.find((e) => e.type === 'WINDOW_UPDATE' && e.stream === 0)?.increment;

const isGrease = (v: number) => (GREASE as readonly number[]).includes(v);
const u16 = (at: number) => record.readUInt16BE(at);

// The hello, field by field: 5 bytes of record, 4 of handshake, 2 of version,
// 32 of random, then the session id, ciphers and compression methods.
let at = 5 + 4 + 2 + 32;
at += 1 + record[at]!;
const ciphers: number[] = [];
for (let i = 0; i < u16(at); i += 2) ciphers.push(u16(at + 2 + i));
at += 2 + u16(at);
at += 1 + record[at]!;
const end = at + 2 + u16(at);
at += 2;

const bodies = new Map<number, Buffer>();
const extensions: number[] = [];
let greaseSeen = 0;
while (at + 4 <= end) {
  const type = u16(at);
  const body = record.subarray(at + 4, at + 4 + u16(at + 2));
  at += 4 + body.length;
  // A resumed visit's pre_shared_key is not what a fresh connection sends.
  if (type === 0x0029) continue;
  bodies.set(type, body);
  // Leading GREASE is the empty one, trailing the one with a byte, as the
  // TLS module tells them apart.
  extensions.push(isGrease(type) ? GREASE[greaseSeen++]! : type);
}

const list16 = (body: Buffer, from = 2) => {
  const out: number[] = [];
  for (let i = from; i < from + body.readUInt16BE(from - 2); i += 2) out.push(body.readUInt16BE(i));
  return out;
};
const normal = (v: number) => (isGrease(v) ? GREASE[0] : v);

const groupsBody = bodies.get(0x000a);
const groups = groupsBody ? list16(groupsBody) : [];
const sharesBody = bodies.get(0x0033);
const keyShares: number[] = [];
if (sharesBody) {
  for (let i = 2; i + 4 <= sharesBody.length; i += 4 + sharesBody.readUInt16BE(i + 2)) {
    keyShares.push(normal(sharesBody.readUInt16BE(i)));
  }
}
const alpnBody = bodies.get(0x0010);
const alpn: string[] = [];
if (alpnBody) {
  for (let i = 2; i < alpnBody.length; i += 1 + alpnBody[i]!) {
    alpn.push(alpnBody.subarray(i + 1, i + 1 + alpnBody[i]!).toString('latin1'));
  }
}
const alpsBody = bodies.get(0x44cd) ?? bodies.get(0x4469);
const alps: string[] = [];
if (alpsBody) {
  for (let i = 2; i < alpsBody.length; i += 1 + alpsBody[i]!) {
    alps.push(alpsBody.subarray(i + 1, i + 1 + alpsBody[i]!).toString('latin1'));
  }
}
const notes: string[] = [];
const ech = bodies.get(0xfe0d);
let echPayload: number | undefined;
if (ech) {
  // outer, KDF, AEAD, config id, the encapsulated key, then the payload.
  const kdf = ech.readUInt16BE(1);
  const aead = ech.readUInt16BE(3);
  const keyLength = ech.readUInt16BE(6);
  echPayload = ech.readUInt16BE(8 + keyLength);
  if (kdf !== 1 || aead !== 1 || keyLength !== 32) {
    notes.push(`ECH sent KDF ${kdf}, AEAD ${aead}, key ${keyLength}; we send 1, 1, 32`);
  }
}
// Extensions neither rustls nor extensions.ts builds go as recorded.
const known = [...BUILT_BY_TLS, 0xff01, 0x0012, 0x0015, 0x4469, 0x44cd, 0xfe0d, 0x0022, 0x001c];
const recorded: Record<string, string> = {};
for (const [type, body] of bodies) {
  if (!isGrease(type) && !known.includes(type)) recorded[String(type)] = body.toString('hex');
}
const delegated = bodies.get(0x0022);
const recordSize = bodies.get(0x001c);
const signatures = bodies.get(0x000d);

const headers = (navigation.headers ?? []).filter(([n]) => !n.startsWith(':'));
const pseudo = (navigation.headers ?? [])
  .filter(([n]) => n.startsWith(':'))
  .map(([n]) => n.slice(1, 2) as 'm' | 'a' | 's' | 'p');
const browser = source.split('_')[0]!;
const capture: Omit<Capture, 'expected'> = {
  source,
  ciphers: ciphers.map(normal),
  signatureSchemes: signatures ? list16(signatures).map(normal) : [],
  greaseNamedGroup: groups.length > 0 && isGrease(groups[0]!),
  namedGroups: groups.map(normal).filter((g) => g !== 0x6399),
  keyShares: keyShares.filter((g) => g !== 0x6399),
  extensions,
  shuffled:
    (browser === 'chrome' || browser === 'edge' || browser === 'brave') &&
    Number.parseInt(source.split('_')[1]!, 10) >= 110,
  alpn,
  ...(alps.length > 0 ? { alps } : {}),
  ...(echPayload === undefined ? {} : { echPayload }),
  ...(delegated ? { delegatedCredentials: list16(delegated) } : {}),
  ...(recordSize ? { recordSizeLimit: recordSize.readUInt16BE(0) } : {}),
  ...(Object.keys(recorded).length > 0 ? { bodies: recorded } : {}),
  http2: {
    settings,
    windowUpdate: windowUpdate ?? 0,
    pseudoHeaderOrder: pseudo,
    ...(navigation.priorityFlag === false
      ? {}
      : { priority: { weight: navigation.weight!, exclusive: navigation.exclusive! } }),
  },
  headers,
};

const dir = fileURLToPath(new URL('../captures/', import.meta.url));
mkdirSync(dir, { recursive: true });
writeFileSync(`${dir}${source}.json`, `${JSON.stringify({ name, capture }, null, 2)}\n`);
console.log(`captures/${source}.json  ${name}  as recorded: ${helloEntry.ja4}`);
for (const note of notes) console.log(`note: ${note}`);
