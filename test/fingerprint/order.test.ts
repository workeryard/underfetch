import { describe, expect, it } from 'vitest';
import {
  arrange,
  headerOrder,
  requestOrder,
  resourceHeaders,
  resourceWeight,
  ResourceError,
  type Resource,
} from '../../src/fingerprint/order';
import { profiles } from '../../src/fingerprint/profiles';

/**
 * Header orders as the browsers wrote them, recorded on 2026-09-25 by a local
 * HTTP/2 server from Edge 153 and Firefox 153 on Windows (see
 * scripts/capture-headers.ts). Values do not matter here, only names.
 */
const EDGE_153 = {
  formPost: [
    'content-length',
    'cache-control',
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
    'upgrade-insecure-requests',
    'content-type',
    'user-agent',
    'origin',
    'accept',
    'sec-fetch-site',
    'sec-fetch-mode',
    'sec-fetch-dest',
    'referer',
    'accept-encoding',
    'accept-language',
    'cookie',
    'priority',
  ],
  fetchGet: [
    'sec-ch-ua-platform',
    'user-agent',
    'sec-ch-ua',
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
  ],
  fetchPostJson: [
    'content-length',
    'sec-ch-ua-platform',
    'user-agent',
    'sec-ch-ua',
    'content-type',
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
  ],
  noStore: [
    'pragma',
    'cache-control',
    'sec-ch-ua-platform',
    'user-agent',
    'sec-ch-ua',
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
  ],
};

const FIREFOX_153 = {
  formPost: [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
    'content-type',
    'content-length',
    'origin',
    'referer',
    'cookie',
    'upgrade-insecure-requests',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'priority',
    'te',
  ],
  fetchGet: [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
    'referer',
    'cookie',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'priority',
    'te',
  ],
  fetchPostJson: [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
    'referer',
    'content-type',
    'content-length',
    'origin',
    'cookie',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'priority',
    'te',
  ],
  customGet: [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
    'referer',
    'authorization',
    'x-api-key',
    'cookie',
    'sec-fetch-dest',
    'sec-fetch-mode',
    'sec-fetch-site',
    'priority',
    'te',
  ],
};

/** The names `profile` sends for `resource`, plus `extra`, in the order we write them. */
function sent(
  profile: (typeof profiles)[keyof typeof profiles],
  resource: 'document' | 'fetch',
  extra: string[],
): string[] {
  const headers = [
    ...resourceHeaders(profile, resource),
    ...extra.map((name) => [name, 'x'] as const),
  ];
  // What a request without those does not carry, the browser did not send either.
  return arrange(headers, headerOrder(profile, resource)).map(([name]) => name);
}

const without = (names: string[], drop: string[]) => names.filter((n) => !drop.includes(n));

describe('header order', () => {
  it('keeps every built-in profile in the order it was captured in', () => {
    for (const [name, profile] of Object.entries(profiles)) {
      const captured = profile.headers.map(([n]) => n.toLowerCase());
      const written = arrange(profile.headers, headerOrder(profile, 'document')).map(([n]) => n);
      expect(written, name).toEqual(captured);
    }
  });

  it('writes Chromium as Edge 153 did', () => {
    const chrome = profiles.chrome;
    const nav = ['content-length', 'cache-control', 'content-type', 'origin', 'referer', 'cookie'];
    // A script-submitted form carries no sec-fetch-user; the profile's does.
    expect(without(sent(chrome, 'document', nav), ['sec-fetch-user'])).toEqual(EDGE_153.formPost);
    expect(sent(chrome, 'fetch', ['referer', 'cookie'])).toEqual(EDGE_153.fetchGet);
    expect(
      sent(chrome, 'fetch', ['content-length', 'content-type', 'origin', 'referer', 'cookie']),
    ).toEqual(EDGE_153.fetchPostJson);
    expect(sent(chrome, 'fetch', ['pragma', 'cache-control', 'referer', 'cookie'])).toEqual(
      EDGE_153.noStore,
    );
  });

  it("puts Brave's sec-gpc straight after accept, page load and fetch() alike", () => {
    const names = (resource: Resource) =>
      arrange(
        resourceHeaders(profiles.brave, resource),
        requestOrder(
          profiles.brave,
          resource,
          resourceHeaders(profiles.brave, resource).map(([n]) => n),
        ),
      ).map(([n]) => n);
    for (const resource of ['document', 'fetch'] as const) {
      const order = names(resource);
      expect(order[order.indexOf('accept') + 1], resource).toBe('sec-gpc');
    }
  });

  it('writes Firefox as Firefox 153 did', () => {
    const firefox = profiles.firefox;
    const nav = ['content-type', 'content-length', 'origin', 'referer', 'cookie'];
    expect(without(sent(firefox, 'document', nav), ['sec-fetch-user'])).toEqual(
      FIREFOX_153.formPost,
    );
    expect(sent(firefox, 'fetch', ['referer', 'cookie'])).toEqual(FIREFOX_153.fetchGet);
    expect(
      sent(firefox, 'fetch', ['content-type', 'content-length', 'origin', 'referer', 'cookie']),
    ).toEqual(FIREFOX_153.fetchPostJson);
    expect(sent(firefox, 'fetch', ['authorization', 'x-api-key', 'referer', 'cookie'])).toEqual(
      FIREFOX_153.customGet,
    );
  });

  it('puts headers no table names at *, alphabetically, or at the end without one', () => {
    const order = ['a', '*', 'z'];
    expect(
      arrange(
        [
          ['z', '1'],
          ['q', '2'],
          ['a', '3'],
          ['b', '4'],
        ],
        order,
      ).map(([n]) => n),
    ).toEqual(['a', 'b', 'q', 'z']);
    expect(
      arrange(
        [
          ['y', '1'],
          ['a', '2'],
        ],
        ['a'],
      ).map(([n]) => n),
    ).toEqual(['a', 'y']);
  });
});

describe('fetch() headers', () => {
  it('are what Chromium sends for fetch(), at its priority', () => {
    const headers = Object.fromEntries(resourceHeaders(profiles.chrome, 'fetch', 'same-site'));
    expect(headers.accept).toBe('*/*');
    expect(headers['sec-fetch-mode']).toBe('cors');
    expect(headers['sec-fetch-dest']).toBe('empty');
    expect(headers['sec-fetch-site']).toBe('same-site');
    expect(headers.priority).toBe('u=1, i');
    expect(headers['upgrade-insecure-requests']).toBeUndefined();
    expect(headers['sec-fetch-user']).toBeUndefined();
    expect(resourceWeight(profiles.chrome, 'fetch')).toBe(220);
  });

  it('are what Firefox sends for fetch(), at its priority', () => {
    const headers = Object.fromEntries(resourceHeaders(profiles.firefox, 'fetch'));
    expect(headers.priority).toBe('u=4');
    expect(headers.te).toBe('trailers');
    expect(resourceWeight(profiles.firefox, 'fetch')).toBe(22);
  });

  it('adds no priority to a Chrome too old to send one', () => {
    const headers = Object.fromEntries(resourceHeaders(profiles.chrome99, 'fetch'));
    expect(headers.priority).toBeUndefined();
  });

  it('are refused for Safari, which nobody has measured', () => {
    expect(() => resourceHeaders(profiles.safari, 'fetch')).toThrow(ResourceError);
  });
});
