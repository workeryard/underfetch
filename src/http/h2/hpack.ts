/**
 * HPACK (RFC 7541): the header compression HTTP/2 insists on.
 *
 * A client can get away with encoding very little — literals without indexing
 * are always legal — but it must decode everything, because the server chooses
 * how to compress and will use the dynamic table and Huffman coding whether we
 * do or not.
 */

import { HUFFMAN_BITS, HUFFMAN_CODE, HUFFMAN_EOS_BITS, STATIC } from './tables';

export class HpackError extends Error {
  override name = 'HpackError';
}

export type Header = readonly [name: string, value: string];

/** RFC 7541 §4.1: an entry costs its text plus 32 bytes of bookkeeping. */
const OVERHEAD = 32;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Writes an integer in HPACK's prefix form: `bits` in this byte, then more. */
function writeInteger(out: number[], value: number, bits: number, first: number): void {
  const max = (1 << bits) - 1;
  if (value < max) {
    out.push(first | value);
    return;
  }
  out.push(first | max);
  let rest = value - max;
  while (rest >= 0x80) {
    out.push((rest & 0x7f) | 0x80);
    rest >>>= 7;
  }
  out.push(rest);
}

/** Reads the same, returning the value and where it ended. */
function readInteger(data: Uint8Array, at: number, bits: number): [value: number, next: number] {
  const max = (1 << bits) - 1;
  let value = data[at]! & max;
  at += 1;
  if (value < max) return [value, at];
  for (let shift = 0; ; shift += 7) {
    if (at >= data.length) throw new HpackError('an integer ran past the end of the block');
    const byte = data[at]!;
    at += 1;
    value += (byte & 0x7f) * 2 ** shift;
    if ((byte & 0x80) === 0) return [value, at];
    if (shift > 21) throw new HpackError('an integer is implausibly long');
  }
}

function huffmanEncode(text: string): number[] {
  const bytes = encoder.encode(text);
  const out: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << HUFFMAN_BITS[byte]!) | HUFFMAN_CODE[byte]!;
    bits += HUFFMAN_BITS[byte]!;
    while (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  // Padding is the leading bits of EOS, which are all ones.
  if (bits > 0) out.push(((buffer << (8 - bits)) | ((1 << (8 - bits)) - 1)) & 0xff);
  return out;
}

/**
 * Decoding walks the code bit by bit. A table-driven decoder would be faster,
 * but headers are small and a wrong table is a silent corruption.
 */
function huffmanDecode(data: Uint8Array): string {
  const out: number[] = [];
  let code = 0;
  let length = 0;
  for (const byte of data) {
    for (let bit = 7; bit >= 0; bit--) {
      code = (code << 1) | ((byte >> bit) & 1);
      length += 1;
      if (length > HUFFMAN_EOS_BITS) throw new HpackError('a Huffman code ran too long');
      for (let symbol = 0; symbol < 256; symbol++) {
        if (HUFFMAN_BITS[symbol] === length && HUFFMAN_CODE[symbol] === code) {
          out.push(symbol);
          code = 0;
          length = 0;
          break;
        }
      }
    }
  }
  // What is left must be padding: fewer than 8 bits, and all ones.
  if (length >= 8 || code !== (1 << length) - 1) {
    throw new HpackError('a Huffman string ended on something other than padding');
  }
  return decoder.decode(new Uint8Array(out));
}

function writeString(out: number[], text: string, huffman: boolean): void {
  if (huffman) {
    const encoded = huffmanEncode(text);
    writeInteger(out, encoded.length, 7, 0x80);
    out.push(...encoded);
    return;
  }
  const raw = encoder.encode(text);
  writeInteger(out, raw.length, 7, 0x00);
  out.push(...raw);
}

function readString(data: Uint8Array, at: number): [text: string, next: number] {
  const huffman = (data[at]! & 0x80) !== 0;
  const [length, start] = readInteger(data, at, 7);
  const end = start + length;
  if (end > data.length) throw new HpackError('a string ran past the end of the block');
  const slice = data.subarray(start, end);
  return [huffman ? huffmanDecode(slice) : decoder.decode(slice), end];
}

/**
 * One end of a connection's header compression. A decoder must live as long as
 * the connection does: the dynamic table is shared state, and reading the
 * second header block needs what the first one put in it.
 */
export class Hpack {
  #dynamic: Header[] = [];
  #size = 0;
  #capacity: number;

  constructor(capacity = 4096) {
    this.#capacity = capacity;
  }

  #entry(index: number): Header {
    if (index >= 1 && index <= STATIC.length) return STATIC[index - 1]!;
    const entry = this.#dynamic[index - STATIC.length - 1];
    if (entry === undefined) throw new HpackError(`no header at index ${index}`);
    return entry;
  }

  #remember(header: Header): void {
    this.#dynamic.unshift(header);
    this.#size += header[0].length + header[1].length + OVERHEAD;
    while (this.#size > this.#capacity && this.#dynamic.length > 0) {
      const dropped = this.#dynamic.pop()!;
      this.#size -= dropped[0].length + dropped[1].length + OVERHEAD;
    }
  }

  /**
   * Encodes headers as literals that never enter either side's dynamic table.
   * It compresses less than a browser would, but it is always legal and it
   * keeps the two tables from drifting apart.
   */
  encode(headers: readonly Header[], huffman = true): Uint8Array {
    const out: number[] = [];
    for (const [name, value] of headers) {
      const indexed = STATIC.findIndex(([known]) => known === name);
      if (indexed === -1) {
        out.push(0x00);
        writeString(out, name, huffman);
      } else {
        writeInteger(out, indexed + 1, 4, 0x00);
      }
      writeString(out, value, huffman);
    }
    return new Uint8Array(out);
  }

  /** Decodes one header block, updating the dynamic table as it goes. */
  decode(block: Uint8Array): Header[] {
    const headers: Header[] = [];
    let at = 0;
    while (at < block.length) {
      const byte = block[at]!;

      if ((byte & 0x80) !== 0) {
        const [index, next] = readInteger(block, at, 7);
        if (index === 0) throw new HpackError('index 0 is not a header');
        headers.push(this.#entry(index));
        at = next;
        continue;
      }

      if ((byte & 0xe0) === 0x20) {
        // A table size update, which may only shrink what we agreed to.
        const [size, next] = readInteger(block, at, 5);
        this.#capacity = size;
        while (this.#size > this.#capacity && this.#dynamic.length > 0) {
          const dropped = this.#dynamic.pop()!;
          this.#size -= dropped[0].length + dropped[1].length + OVERHEAD;
        }
        at = next;
        continue;
      }

      // Literal, either with incremental indexing (0x40) or without.
      const indexing = (byte & 0x40) !== 0;
      const prefix = indexing ? 6 : 4;
      const [index, afterIndex] = readInteger(block, at, prefix);
      let name: string;
      let cursor = afterIndex;
      if (index === 0) {
        [name, cursor] = readString(block, cursor);
      } else {
        name = this.#entry(index)[0];
      }
      const [value, next] = readString(block, cursor);
      const header: Header = [name, value];
      headers.push(header);
      if (indexing) this.#remember(header);
      at = next;
    }
    return headers;
  }
}
