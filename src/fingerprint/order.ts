/**
 * The order a browser writes its headers in, and what it sends for a request
 * that is not a page load.
 *
 * `Headers` sorts its names, so without this every request went out
 * alphabetically — `accept, accept-encoding, accept-language, priority, …` —
 * which no browser does and a bot check can read at a glance.
 *
 * Measured on 2026-09-25 with the browsers themselves, not taken from any
 * library: Edge 153 and Firefox 153 on Windows, pointed at a local
 * HTTP/2 server that recorded every request's raw header order and stream
 * weight — a navigation, a form POST, fetch() GET and POST, XHR, a CORS
 * preflight, `cache: 'no-store'`, and requests carrying authorization and
 * other headers of the page's own. Each navigation order agrees with the
 * captures the profiles were built from. Chrome 154, measured after, wrote
 * every request exactly as Edge 153 did, a page's own headers included; so
 * did Brave, which adds only `sec-gpc`. There is no Safari measurement.
 *
 * `*` marks where headers the table does not name go, alphabetically — the
 * caller's own, such as `authorization`. Firefox puts a page's own headers
 * right after `referer`, in the order they were set. Chromium does not keep
 * one place for them: it lays them out through a hash table, so their slot
 * moves with how many there are. `*` there is the slot most of the measured
 * ones took, an approximation, not the browser's rule.
 */

import type { Impersonation } from './profiles';

/** What a request is: a page load, or a script's call to an API. */
export type Resource = 'document' | 'fetch';

/** Where the page asking for it stands relative to the target. */
export type FetchSite = 'same-origin' | 'same-site' | 'cross-site';

export type Family = 'chromium' | 'firefox' | 'safari';

export const ANY = '*';

const CHROMIUM_DOCUMENT = [
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
  'sec-fetch-user',
  'sec-fetch-dest',
  'referer',
  'accept-encoding',
  'accept-language',
  'cookie',
  'priority',
  ANY,
];

const CHROMIUM_FETCH = [
  'content-length',
  'pragma',
  'cache-control',
  'sec-ch-ua-platform',
  ANY,
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
];

const FIREFOX_DOCUMENT = [
  'user-agent',
  'accept',
  'accept-language',
  'accept-encoding',
  'content-type',
  'content-length',
  'origin',
  'referer',
  ANY,
  'cookie',
  'upgrade-insecure-requests',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'sec-fetch-user',
  'priority',
  'pragma',
  'cache-control',
  'te',
];

// content-type is the page's own here, so it sorts among the rest in `*`.
const FIREFOX_FETCH = [
  'user-agent',
  'accept',
  'accept-language',
  'accept-encoding',
  'referer',
  ANY,
  'content-length',
  'origin',
  'cookie',
  'sec-fetch-dest',
  'sec-fetch-mode',
  'sec-fetch-site',
  'priority',
  'pragma',
  'cache-control',
  'te',
];

const ORDERS: Record<Family, Partial<Record<Resource, readonly string[]>>> = {
  chromium: { document: CHROMIUM_DOCUMENT, fetch: CHROMIUM_FETCH },
  firefox: { document: FIREFOX_DOCUMENT, fetch: FIREFOX_FETCH },
  safari: {},
};

/**
 * What changes between a page load and a script's fetch(), measured:
 * the `priority` header, and the weight on the HEADERS frame.
 */
const FETCH_PRIORITY: Record<Exclude<Family, 'safari'>, { header: string; weight: number }> = {
  chromium: { header: 'u=1, i', weight: 220 },
  firefox: { header: 'u=4', weight: 22 },
};

export class ResourceError extends Error {
  override name = 'ResourceError';
}

/**
 * The order to write `profile`'s headers in for this kind of request. A
 * profile of no known family keeps its own headers' order, with anything else
 * after them.
 */
export function headerOrder(profile: Impersonation, resource: Resource): readonly string[] {
  const measured = profile.family === undefined ? undefined : ORDERS[profile.family][resource];
  return measured ?? [...profile.headers.map(([name]) => name.toLowerCase()), ANY];
}

/**
 * `headers` in `order`: named ones where the order puts them, the rest
 * alphabetically at `*`, or at the end when the order has no `*`.
 */
export function arrange(
  headers: Iterable<readonly [string, string]>,
  order: readonly string[],
): [string, string][] {
  const rank = new Map(order.map((name, i) => [name, i]));
  const unnamed = rank.get(ANY) ?? order.length;
  return [...headers]
    .map(([name, value]): [string, string] => [name.toLowerCase(), value])
    .map((header, i) => ({ header, i, at: rank.get(header[0]) ?? unnamed }))
    .sort((a, b) =>
      a.at !== b.at
        ? a.at - b.at
        : a.at === unnamed
          ? a.header[0].localeCompare(b.header[0])
          : a.i - b.i,
    )
    .map(({ header }) => header);
}

/** Headers a page load sends that a script's fetch() does not. */
const NAVIGATION_ONLY = new Set(['upgrade-insecure-requests', 'sec-fetch-user']);

/**
 * `profile`'s headers as the browser sends them for `resource`. A page load is
 * the profile as captured; a fetch() accepts any type, takes cors and empty for
 * mode and dest, `site` for sec-fetch-site, and the browser's fetch priority,
 * and drops what only a navigation carries.
 */
export function resourceHeaders(
  profile: Impersonation,
  resource: Resource,
  site: FetchSite = 'same-origin',
): (readonly [string, string])[] {
  if (resource === 'document') return [...profile.headers];
  const family = profile.family;
  if (family === undefined || family === 'safari') {
    throw new ResourceError(
      `no ${family ?? 'custom'} fetch() has been measured, so none is imitated; ` +
        'send it as a page load, or set its headers yourself',
    );
  }
  const replaced: Record<string, string> = {
    accept: '*/*',
    'sec-fetch-site': site,
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    priority: FETCH_PRIORITY[family].header,
  };
  return profile.headers
    .filter(([name]) => !NAVIGATION_ONLY.has(name.toLowerCase()))
    .map(([name, value]) => [name, replaced[name.toLowerCase()] ?? value] as const);
}

/** The HEADERS frame weight for `resource`, where it differs from a page load's. */
export function resourceWeight(profile: Impersonation, resource: Resource): number | undefined {
  if (resource === 'document' || profile.family === undefined || profile.family === 'safari') {
    return undefined;
  }
  return FETCH_PRIORITY[profile.family].weight;
}

/** The family a capture's source names: `chrome_150…`, `firefox_144…`. */
export function familyOf(source: string): Family | undefined {
  const browser = source.split('_')[0];
  if (browser === 'chrome' || browser === 'edge') return 'chromium';
  if (browser === 'firefox' || browser === 'tor') return 'firefox';
  if (browser === 'safari') return 'safari';
  return undefined;
}
