import { describe, expect, it } from 'vitest';
import { CookieJar } from '../src/cookies';

const at = (url: string) => new URL(url);

describe('cookies', () => {
  it('sends back what a host set, and only to that host', () => {
    const jar = new CookieJar();
    jar.store(at('https://api.example.com/v1/models'), ['session=abc; Path=/']);

    expect(jar.header(at('https://api.example.com/v1/chat'))).toBe('session=abc');
    expect(jar.header(at('https://other.example/'))).toBeNull();
    // No Domain attribute means that exact host, not its subdomains.
    expect(jar.header(at('https://sub.api.example.com/'))).toBeNull();
  });

  it('widens to subdomains when the server asks, but no further', () => {
    const jar = new CookieJar();
    jar.store(at('https://api.example.com/'), ['a=1; Domain=example.com']);
    expect(jar.header(at('https://other.example.com/'))).toBe('a=1');

    // A site cannot set a cookie for somebody else's domain.
    jar.store(at('https://api.example.com/'), ['b=2; Domain=evil.test']);
    expect(jar.header(at('https://evil.test/'))).toBeNull();
  });

  it('respects the path it was scoped to', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/'), ['deep=1; Path=/admin']);

    expect(jar.header(at('https://e.com/admin'))).toBe('deep=1');
    expect(jar.header(at('https://e.com/admin/users'))).toBe('deep=1');
    // `/administrator` is not inside `/admin`.
    expect(jar.header(at('https://e.com/administrator'))).toBeNull();
    expect(jar.header(at('https://e.com/'))).toBeNull();
  });

  it('defaults a cookie to the directory it came from', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/v1/models'), ['a=1']);
    expect(jar.header(at('https://e.com/v1/chat'))).toBe('a=1');
    expect(jar.header(at('https://e.com/v2/chat'))).toBeNull();
  });

  it('keeps a Secure cookie off plain http', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/'), ['s=1; Path=/; Secure']);
    expect(jar.header(at('https://e.com/'))).toBe('s=1');
    expect(jar.header(at('http://e.com/'))).toBeNull();
  });

  it('forgets a cookie once it expires', () => {
    const jar = new CookieJar();
    const now = 1_000_000;
    jar.store(at('https://e.com/'), ['short=1; Path=/; Max-Age=10'], now);

    expect(jar.header(at('https://e.com/'), now + 5_000)).toBe('short=1');
    expect(jar.header(at('https://e.com/'), now + 11_000)).toBeNull();
  });

  it('lets a server delete one by dating it in the past', () => {
    const jar = new CookieJar();
    const now = 2_000_000;
    jar.store(at('https://e.com/'), ['a=1; Path=/'], now);
    expect(jar.header(at('https://e.com/'), now)).toBe('a=1');

    jar.store(at('https://e.com/'), ['a=; Path=/; Max-Age=0'], now);
    expect(jar.header(at('https://e.com/'), now)).toBeNull();
  });

  it('prefers Max-Age over Expires, whichever came first', () => {
    const jar = new CookieJar();
    const now = 3_000_000;
    jar.store(
      at('https://e.com/'),
      ['a=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60'],
      now,
    );
    expect(jar.header(at('https://e.com/'), now)).toBe('a=1');
  });

  it('replaces a cookie of the same name, domain and path', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/'), ['a=old; Path=/']);
    jar.store(at('https://e.com/'), ['a=new; Path=/']);

    expect(jar.header(at('https://e.com/'))).toBe('a=new');
    expect(jar.all()).toHaveLength(1);
  });

  it('sends the deepest path first, as servers expect', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/'), ['wide=1; Path=/']);
    jar.store(at('https://e.com/'), ['narrow=1; Path=/admin/users']);

    expect(jar.header(at('https://e.com/admin/users'))).toBe('narrow=1; wide=1');
  });

  it('ignores a header that is not a cookie', () => {
    const jar = new CookieJar();
    jar.store(at('https://e.com/'), ['', 'nonsense', '=novalue']);
    expect(jar.all()).toEqual([]);
  });
});
