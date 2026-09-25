import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { blinkHash, blinkTableOrder } from '../../src/fingerprint/blink-order';
import { arrange, requestOrder, resourceHeaders } from '../../src/fingerprint/order';
import { profiles } from '../../src/fingerprint/profiles';

const fixture = JSON.parse(
  readFileSync(new URL('./fixtures/chromium-table-orders.json', import.meta.url), 'utf8'),
) as { cases: { set: string[]; chrome154: string[] }[] };

const BROWSER = ['sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'user-agent'];

describe('Blink header table', () => {
  it('hashes names as Chromium does', () => {
    // Computed independently from Chromium's rapidhash and case-folding reader.
    expect(blinkHash('sec-ch-ua-platform').toString(16)).toBe('ffbec3');
    expect(blinkHash('user-agent').toString(16)).toBe('c21178');
    expect(blinkHash('Authorization')).toBe(blinkHash('authorization'));
    expect(
      blinkHash('x-very-long-header-name-that-exceeds-forty-eight-bytes-for-sure'),
    ).toBeGreaterThan(0);
  });

  it(`writes each of the ${fixture.cases.length} captured sets in the order Chrome 154 did`, () => {
    const wrong = fixture.cases.filter(
      ({ set, chrome154 }) =>
        JSON.stringify(blinkTableOrder([...set, ...BROWSER])) !== JSON.stringify(chrome154),
    );
    expect(wrong).toEqual([]);
  });

  it("places a page's own headers where Chrome did, through its header table", () => {
    const chrome = profiles.chrome;
    const request = (extra: string[]) => {
      const headers = [
        ...resourceHeaders(chrome, 'fetch'),
        ...extra.map((name) => [name, 'x'] as const),
      ];
      const order = requestOrder(
        chrome,
        'fetch',
        headers.map(([name]) => name),
      );
      return arrange(headers, order).map(([name]) => name);
    };
    // Edge 153 and Chrome 154 wrote exactly these.
    expect(request(['authorization', 'x-api-key', 'referer', 'cookie'])).toEqual([
      'sec-ch-ua-platform',
      'authorization',
      'user-agent',
      'sec-ch-ua',
      'x-api-key',
      'sec-ch-ua-mobile',
      'accept',
      'sec-fetch-site',
      'sec-fetch-mode',
      'sec-fetch-dest',
      'referer',
      'accept-encoding',
      'accept-language',
      'cookie',
      'priority',
    ]);
    expect(
      request([
        'content-length',
        'content-type',
        'authorization',
        'x-api-key',
        'origin',
        'referer',
        'cookie',
      ]),
    ).toEqual([
      'content-length',
      'sec-ch-ua-platform',
      'authorization',
      'user-agent',
      'sec-ch-ua',
      'content-type',
      'x-api-key',
      'sec-ch-ua-mobile',
      'accept',
      'origin',
      'sec-fetch-site',
      'sec-fetch-mode',
      'sec-fetch-dest',
      'referer',
      'accept-encoding',
      'accept-language',
      'cookie',
      'priority',
    ]);
  });
});
