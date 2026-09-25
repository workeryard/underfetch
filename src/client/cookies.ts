/**
 * A cookie jar (RFC 6265).
 *
 * Any API that logs you in and then expects you to stay logged in needs one,
 * and `fetch` on a Worker has nowhere to keep them. This is deliberately a
 * plain object the caller holds: a jar shared by accident between two users
 * would hand one of them the other's session.
 */

export interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  /** Unix milliseconds, or undefined for a cookie that dies with the session. */
  expires?: number | undefined;
  secure: boolean;
  /** True when no Domain attribute was given, so only that exact host matches. */
  hostOnly: boolean;
}

/** RFC 6265 §5.1.3: the same host, or a parent of it on a label boundary. */
function domainMatches(host: string, domain: string): boolean {
  if (host === domain) return true;
  return host.endsWith(`.${domain}`);
}

/** RFC 6265 §5.1.4: the same path, or a prefix of it ending at a segment. */
function pathMatches(requested: string, path: string): boolean {
  if (requested === path) return true;
  if (!requested.startsWith(path)) return false;
  return path.endsWith('/') || requested[path.length] === '/';
}

/** The directory of a URL, which is where a cookie without a Path belongs. */
function defaultPath(pathname: string): string {
  const cut = pathname.lastIndexOf('/');
  return cut <= 0 ? '/' : pathname.slice(0, cut);
}

function parseOne(header: string, url: URL, now: number): Cookie | null {
  const [pair, ...attributes] = header.split(';');
  const equals = pair?.indexOf('=') ?? -1;
  if (pair === undefined || equals <= 0) return null;

  const cookie: Cookie = {
    name: pair.slice(0, equals).trim(),
    value: pair.slice(equals + 1).trim(),
    domain: url.hostname,
    path: defaultPath(url.pathname),
    secure: false,
    hostOnly: true,
  };

  let maxAge: number | undefined;
  for (const attribute of attributes) {
    const at = attribute.indexOf('=');
    const name = (at === -1 ? attribute : attribute.slice(0, at)).trim().toLowerCase();
    const value = at === -1 ? '' : attribute.slice(at + 1).trim();

    if (name === 'domain' && value !== '') {
      const domain = value.replace(/^\./, '').toLowerCase();
      // A site may widen a cookie to its parents, never to somebody else's.
      if (!domainMatches(url.hostname, domain)) return null;
      cookie.domain = domain;
      cookie.hostOnly = false;
    } else if (name === 'path' && value.startsWith('/')) {
      cookie.path = value;
    } else if (name === 'secure') {
      cookie.secure = true;
    } else if (name === 'max-age') {
      const seconds = Number(value);
      if (Number.isFinite(seconds)) maxAge = now + seconds * 1000;
    } else if (name === 'expires' && maxAge === undefined) {
      const when = Date.parse(value);
      if (!Number.isNaN(when)) cookie.expires = when;
    }
  }
  // Max-Age wins over Expires, whatever order they arrived in.
  if (maxAge !== undefined) cookie.expires = maxAge;
  return cookie;
}

/** Whether `value` is a cookie as `all()` gives them out, from wherever it was kept. */
function isCookie(value: unknown): value is Cookie {
  if (typeof value !== 'object' || value === null) return false;
  const c = value as Record<string, unknown>;
  return (
    typeof c.name === 'string' &&
    c.name !== '' &&
    typeof c.value === 'string' &&
    typeof c.domain === 'string' &&
    c.domain !== '' &&
    typeof c.path === 'string' &&
    c.path.startsWith('/') &&
    (c.expires === undefined || (typeof c.expires === 'number' && Number.isFinite(c.expires))) &&
    typeof c.secure === 'boolean' &&
    typeof c.hostOnly === 'boolean'
  );
}

export class CookieJar {
  #cookies: Cookie[] = [];

  /**
   * A jar holding `cookies`, as an earlier jar's `all()` gave them — kept in
   * KV, a Durable Object or anywhere else in between. What is malformed or
   * already expired is left out rather than trusted.
   */
  constructor(cookies: readonly unknown[] = [], now = Date.now()) {
    this.add(cookies, now);
  }

  /**
   * Takes cookies as `all()` gives them out, replacing any held with the
   * same name, domain and path. What is malformed or expired is left out.
   */
  add(cookies: readonly unknown[], now = Date.now()): void {
    for (const cookie of cookies) {
      if (!isCookie(cookie)) continue;
      if (cookie.expires !== undefined && cookie.expires <= now) continue;
      const { name, value, domain, path, expires, secure, hostOnly } = cookie;
      this.#cookies = this.#cookies.filter(
        (held) =>
          !(held.name === name && held.domain === domain.toLowerCase() && held.path === path),
      );
      this.#cookies.push({
        name,
        value,
        domain: domain.toLowerCase(),
        path,
        ...(expires === undefined ? {} : { expires }),
        secure,
        hostOnly,
      });
    }
  }

  /** Takes the `set-cookie` headers of one response. */
  store(url: URL, headers: readonly string[], now = Date.now()): void {
    for (const header of headers) {
      const cookie = parseOne(header, url, now);
      if (cookie === null) continue;
      // A new value for the same name, domain and path replaces the old one.
      this.#cookies = this.#cookies.filter(
        (held) =>
          !(
            held.name === cookie.name &&
            held.domain === cookie.domain &&
            held.path === cookie.path
          ),
      );
      // An expiry in the past is how a server deletes a cookie.
      if (cookie.expires !== undefined && cookie.expires <= now) continue;
      this.#cookies.push(cookie);
    }
  }

  /** The `cookie` header for this URL, or null when nothing applies. */
  header(url: URL, now = Date.now()): string | null {
    const secure = url.protocol === 'https:';
    const matching = this.#cookies.filter((cookie) => {
      if (cookie.expires !== undefined && cookie.expires <= now) return false;
      if (cookie.secure && !secure) return false;
      if (
        cookie.hostOnly
          ? url.hostname !== cookie.domain
          : !domainMatches(url.hostname, cookie.domain)
      ) {
        return false;
      }
      return pathMatches(url.pathname, cookie.path);
    });
    if (matching.length === 0) return null;
    // RFC 6265 §5.4: longer paths first, which is what servers expect.
    return [...matching]
      .sort((a, b) => b.path.length - a.path.length)
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join('; ');
  }

  /** Everything still held, with anything expired dropped on the way out. */
  all(now = Date.now()): Cookie[] {
    this.#cookies = this.#cookies.filter(
      (cookie) => cookie.expires === undefined || cookie.expires > now,
    );
    return [...this.#cookies];
  }

  clear(): void {
    this.#cookies = [];
  }
}
