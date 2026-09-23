import { describe, expect, it } from 'vitest';
import { Hpack, HpackError } from '../../src/http/h2/hpack';

/**
 * The examples are RFC 7541's own (Appendix C), which is the only way to be
 * sure a codec is right rather than merely self-consistent: these byte strings
 * were produced by the people who wrote the specification.
 */

/** The RFC prints hex in groups of two bytes, so whitespace is not a separator. */
const bytes = (hex: string) =>
  new Uint8Array((hex.replace(/\s+/g, '').match(/../g) ?? []).map((b) => parseInt(b, 16)));

describe('hpack', () => {
  it('reads an indexed header from the static table', () => {
    // C.2.4: index 2 is `:method: GET`.
    expect(new Hpack().decode(bytes('82'))).toEqual([[':method', 'GET']]);
  });

  it('reads a literal that never enters the table', () => {
    // C.2.2: `:path: /sample/path`, without indexing.
    expect(new Hpack().decode(bytes('040c 2f73 616d 706c 652f 7061 7468'))).toEqual([
      [':path', '/sample/path'],
    ]);
  });

  it('reads a literal with a new name and remembers it', () => {
    // C.2.1: `custom-key: custom-header`, with incremental indexing.
    const hpack = new Hpack();
    const block = bytes('400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572');
    expect(hpack.decode(block)).toEqual([['custom-key', 'custom-header']]);
    // 62 is the first dynamic entry, so the table took it.
    expect(hpack.decode(bytes('be'))).toEqual([['custom-key', 'custom-header']]);
  });

  it('follows a whole request sequence through the dynamic table', () => {
    // C.3: three requests, where the third leans on what the first two stored.
    const hpack = new Hpack();
    expect(hpack.decode(bytes('8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d'))).toEqual([
      [':method', 'GET'],
      [':scheme', 'http'],
      [':path', '/'],
      [':authority', 'www.example.com'],
    ]);
    expect(hpack.decode(bytes('8286 84be 5808 6e6f 2d63 6163 6865'))).toEqual([
      [':method', 'GET'],
      [':scheme', 'http'],
      [':path', '/'],
      [':authority', 'www.example.com'],
      ['cache-control', 'no-cache'],
    ]);
  });

  it('decodes Huffman-coded strings', () => {
    // C.4.1: the same request, with every literal Huffman coded.
    expect(new Hpack().decode(bytes('8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff'))).toEqual([
      [':method', 'GET'],
      [':scheme', 'http'],
      [':path', '/'],
      [':authority', 'www.example.com'],
    ]);
  });

  it('decodes a Huffman-coded status and header, as a response carries', () => {
    // C.6.1's first field: `:status: 302`, literal with indexing, Huffman.
    const hpack = new Hpack();
    expect(hpack.decode(bytes('4882 6402'))).toEqual([[':status', '302']]);
    // Having indexed it, the next block can name it by number alone.
    expect(hpack.decode(bytes('be'))).toEqual([[':status', '302']]);
  });

  it('obeys a dynamic table size update', () => {
    const hpack = new Hpack();
    hpack.decode(bytes('400a 6375 7374 6f6d 2d6b 6579 0361 6161')); // custom-key: aaa
    expect(hpack.decode(bytes('be'))).toEqual([['custom-key', 'aaa']]);

    // `0x20` sets the capacity to zero, which must clear everything stored.
    hpack.decode(bytes('20'));
    expect(() => hpack.decode(bytes('be'))).toThrow(HpackError);
  });

  it('round-trips what it encodes, Huffman or not', () => {
    const headers = [
      [':method', 'POST'],
      [':authority', 'api.example.com'],
      [':path', '/v1/chat/completions?stream=true'],
      ['authorization', 'Bearer sk-0123456789'],
      ['x-odd-name', 'a value with spaces and ünïcode'],
    ] as const;

    for (const huffman of [true, false]) {
      const encoded = new Hpack().encode(headers, huffman);
      expect(new Hpack().decode(encoded)).toEqual(headers.map((h) => [...h]));
    }
  });

  it('refuses a block that lies about its lengths', () => {
    // A literal claiming 15 bytes of name with only two present.
    expect(() => new Hpack().decode(bytes('00 0f 61 62'))).toThrow(HpackError);
    // Index 0 is reserved and never names a header.
    expect(() => new Hpack().decode(bytes('80'))).toThrow(HpackError);
    // An index past the end of both tables.
    expect(() => new Hpack().decode(bytes('ff 00'))).toThrow(HpackError);
  });

  it('evicts from the dynamic table once it is full', () => {
    const hpack = new Hpack(64); // room for one small entry, not two
    hpack.decode(bytes('400a 6375 7374 6f6d 2d6b 6579 0361 6161')); // custom-key: aaa
    hpack.decode(bytes('400b 6375 7374 6f6d 2d6b 6579 3103 6262 62')); // a second one
    // The first is gone, so its old index now holds the newer entry or nothing.
    expect(hpack.decode(bytes('be'))[0]?.[1]).toBe('bbb');
  });
});
