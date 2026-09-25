/**
 * Where Chromium puts a page's own headers in a fetch().
 *
 * They do not keep one place. Blink holds a request's headers in a hash
 * table — `HTTPHeaderMap`, a WTF `HashMap` with a case-folding hash — and
 * hands them to the network stack in table order, so their slots, and
 * those of `user-agent` and the `sec-ch-ua` hints kept with them, follow
 * from each name's hash and from how full the table is.
 *
 * This is that table, from Chromium's source (third_party/blink/renderer/
 * platform/wtf/hash_table.h, wtf/text/case_folding_hash.h, and
 * third_party/rapidhash/rapidhash.h), and checked against the browser: it
 * reproduces every order Chrome 154 and Edge 153 wrote across 63 captured
 * requests, 40 of them random sets of one to twelve headers predicted before
 * they were captured (see test/fingerprint/blink-order.test.ts).
 *
 * - The hash is rapidhash over the name folded to lower case and read as
 *   UTF-16, masked to 24 bits, with 0 replaced by 0x800000.
 * - The table starts at 8 buckets and doubles once it is half full,
 *   re-inserting in bucket order; a collision probes +1, +2, +3… further.
 * - The page's headers go in first, in name order as `Headers` lists them,
 *   then `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `user-agent`.
 *   Two other orders of those four fit the captures equally; this one is the
 *   order Chrome writes them in on a page load.
 */

const MASK64 = (1n << 64n) - 1n;
const SEED = 0xbdd89aa982704029n;
const SECRET = [0x2d358dccaa6c78a5n, 0x8bb84b93962eacc9n, 0x4b33a62ed433d4a3n] as const;

function mul128(a: bigint, b: bigint): [bigint, bigint] {
  const product = a * b;
  return [product & MASK64, (product >> 64n) & MASK64];
}

function mix(a: bigint, b: bigint): bigint {
  const [low, high] = mul128(a, b);
  return low ^ high;
}

/**
 * `CaseFoldingHashReader<LChar>`: one Latin-1 byte becomes one folded UTF-16
 * unit, so reads are in characters while `len` counts UTF-16 bytes.
 */
function reader(name: string) {
  const units = [...name].map((c) => BigInt(c.toLowerCase().charCodeAt(0)));
  return {
    len: units.length * 2,
    r32: (at: number) => units[at]! | (units[at + 1]! << 16n),
    r64: (at: number) =>
      units[at]! | (units[at + 1]! << 16n) | (units[at + 2]! << 32n) | (units[at + 3]! << 48n),
    small: (at: number) => units[at]!,
  };
}

/** rapidhash_internal, with the reader's offsets in characters (bytes / 2). */
function rapidhash(name: string): bigint {
  const { len, r32, r64, small } = reader(name);
  let seed = SEED ^ mix(SEED ^ SECRET[0], SECRET[1]) ^ BigInt(len);
  let a: bigint;
  let b: bigint;
  if (len <= 16) {
    if (len >= 4) {
      const last = (len - 4) / 2;
      a = (r32(0) << 32n) | r32(last);
      const delta = ((len & 24) >> (len >> 3)) / 2;
      b = (r32(delta) << 32n) | r32(last - delta);
    } else if (len > 0) {
      a = small(0);
      b = 0n;
    } else {
      a = b = 0n;
    }
  } else {
    let i = len;
    let p = 0;
    if (i > 48) {
      let see1 = seed;
      let see2 = seed;
      do {
        seed = mix(r64(p) ^ SECRET[0], r64(p + 4) ^ seed);
        see1 = mix(r64(p + 8) ^ SECRET[1], r64(p + 12) ^ see1);
        see2 = mix(r64(p + 16) ^ SECRET[2], r64(p + 20) ^ see2);
        p += 24;
        i -= 48;
      } while (i >= 48);
      seed ^= see1 ^ see2;
    }
    if (i > 16) {
      seed = mix(r64(p) ^ SECRET[2], r64(p + 4) ^ seed ^ SECRET[1]);
      if (i > 32) seed = mix(r64(p + 8) ^ SECRET[2], r64(p + 12) ^ seed);
    }
    a = r64(p + (i - 16) / 2);
    b = r64(p + (i - 8) / 2);
  }
  [a, b] = mul128(a ^ SECRET[1], b ^ seed);
  return mix(a ^ SECRET[0] ^ BigInt(len), b ^ SECRET[1]);
}

/** `DeprecatedCaseFoldingHash::GetHash`: the low 24 bits, never 0. */
export function blinkHash(name: string): number {
  const hash = Number(rapidhash(name) & 0xffffffn);
  return hash === 0 ? 0x800000 : hash;
}

/** The headers Chromium keeps in that table beside the page's own. */
const BROWSER_IN_TABLE = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'user-agent'];

/**
 * The order Chromium writes `names` in: the page's own headers and those of
 * `BROWSER_IN_TABLE` among them, as the table lays them out.
 */
export function blinkTableOrder(names: Iterable<string>): string[] {
  const all = [...new Set([...names].map((n) => n.toLowerCase()))];
  const browser = BROWSER_IN_TABLE.filter((n) => all.includes(n));
  const own = all.filter((n) => !BROWSER_IN_TABLE.includes(n)).sort();

  let slots: (string | undefined)[] = [];
  let count = 0;
  const place = (name: string) => {
    const mask = slots.length - 1;
    let i = blinkHash(name) & mask;
    for (let probe = 1; slots[i] !== undefined; probe++) i = (i + probe) & mask;
    slots[i] = name;
  };
  for (const name of [...own, ...browser]) {
    if (slots.length === 0) slots = new Array<string | undefined>(8);
    place(name);
    count++;
    if (count * 2 >= slots.length) {
      const old = slots;
      slots = new Array<string | undefined>(old.length * 2);
      for (const kept of old) if (kept !== undefined) place(kept);
    }
  }
  return slots.filter((name): name is string => name !== undefined);
}
