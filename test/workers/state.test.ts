import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CookieJar } from '../../src/client/cookies';
import { profiles } from '../../src/fingerprint/profiles';
import { withFingerprints } from '../../src/fingerprint/custom';
import {
  fromBase64,
  identityOf,
  readState,
  restoredProfile,
  SessionStateError,
  STATE_VERSION,
  toBase64,
  type SessionState,
} from '../../src/workers/state';
import { initSync, TicketStore } from '../../rust-tls/pkg/underfetch_tls';

initSync({
  module: new WebAssembly.Module(
    readFileSync(
      fileURLToPath(new URL('../../rust-tls/pkg/underfetch_tls_bg.wasm', import.meta.url)),
    ),
  ),
});

const named = (name: string) => profiles[name as keyof typeof profiles];

const saved = (overrides: Partial<SessionState> = {}): SessionState => ({
  version: STATE_VERSION,
  savedAt: 1,
  impersonate: { name: 'chrome', ja4: profiles.chrome.expected.ja4 },
  cookies: [],
  tickets: '',
  ...overrides,
});

describe('readState', () => {
  it('takes the object or its JSON alike', () => {
    const state = saved();
    expect(readState(state)).toEqual(state);
    expect(readState(JSON.stringify(state))).toEqual(state);
    // A Durable Object hands back a structured clone, not the same object.
    expect(readState(structuredClone(state))).toEqual(state);
  });

  it('refuses a newer version rather than misreading it', () => {
    expect(() => readState(saved({ version: STATE_VERSION + 1 }))).toThrow(/newer/);
  });

  it('refuses what is not a saved session', () => {
    for (const bad of ['not json', '42', JSON.stringify({ version: 1 }), JSON.stringify(null)]) {
      expect(() => readState(bad), bad).toThrow(SessionStateError);
    }
  });
});

describe('restoredProfile', () => {
  const chrome = saved().impersonate;

  it('restores the browser it was saved as, by name or by an alias of it', () => {
    expect(restoredProfile(chrome, undefined, named)).toBe(profiles.chrome);
    expect(restoredProfile(chrome, profiles.chrome150, named)).toBe(profiles.chrome150);
  });

  it('refuses another browser', () => {
    expect(() => restoredProfile(chrome, profiles.firefox, named)).toThrow(/saved as chrome/);
  });

  it('asks for a profile of your own to be passed again', () => {
    const custom = { ja4: profiles.safari.expected.ja4 };
    expect(() => restoredProfile(custom, undefined, named)).toThrow(/pass it again/);
    expect(restoredProfile(custom, profiles.safari, named)).toBe(profiles.safari);
  });

  it('keeps a session saved without a profile without one', () => {
    expect(restoredProfile(null, undefined, named)).toBeUndefined();
    expect(() => restoredProfile(null, profiles.chrome, named)).toThrow(/without one/);
  });
});

describe('a profile built from strings', () => {
  const input = { akamai: '1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s' };
  const custom = withFingerprints(profiles.chrome150, input);
  const saved = identityOf(custom, 'chrome150', input);

  it('comes back by itself from what the state recorded', () => {
    const back = restoredProfile(saved, undefined, named);
    expect(back?.expected).toEqual(custom.expected);
  });

  it('is refused under the plain profile it was built on', () => {
    expect(() => restoredProfile(saved, profiles.chrome150, named)).toThrow(/akamai/);
  });

  it('still reads an older state, which recorded a name and a JA4', () => {
    const old = { name: 'chrome', ja4: profiles.chrome.expected.ja4 };
    expect(restoredProfile(old, undefined, named)).toBe(profiles.chrome);
  });
});

describe('CookieJar from saved cookies', () => {
  it('restores what all() gave out, and nothing malformed or expired', () => {
    const jar = new CookieJar();
    jar.store(new URL('https://example.com/'), ['sid=abc; Path=/', 'pref=dark; Max-Age=60']);
    const kept = JSON.parse(JSON.stringify(jar.all())) as unknown[];

    const restored = new CookieJar([
      ...kept,
      {
        name: 'old',
        value: 'x',
        domain: 'example.com',
        path: '/',
        expires: 1,
        secure: false,
        hostOnly: true,
      },
      { name: 'broken' },
      'nonsense',
    ]);

    expect(restored.header(new URL('https://example.com/'))).toBe('sid=abc; pref=dark');
    expect(restored.all().map((c) => c.name)).toEqual(['sid', 'pref']);
  });

  it('replaces a cookie it already holds', () => {
    const jar = new CookieJar([
      { name: 'a', value: '1', domain: 'example.com', path: '/', secure: false, hostOnly: true },
    ]);
    jar.add([
      { name: 'a', value: '2', domain: 'Example.com', path: '/', secure: false, hostOnly: true },
    ]);
    expect(jar.header(new URL('https://example.com/'))).toBe('a=2');
  });
});

describe('TicketStore export', () => {
  it('writes an empty store in its format, and takes it back', () => {
    const store = new TicketStore();
    const empty = store.export();
    expect([...empty]).toEqual([1, 0, 0, 0, 0]);
    expect(new TicketStore().import(empty)).toBe(0);
    // Through the base64 the state carries it in.
    expect(fromBase64(toBase64(empty))).toEqual(empty);
  });

  it('refuses bytes of another layout, or cut short', () => {
    const store = new TicketStore();
    expect(() => store.import(new Uint8Array([2, 0, 0, 0, 0]))).toThrow();
    expect(() => store.import(new Uint8Array([1, 0, 0, 0, 1, 0]))).toThrow();
    expect(() => store.import(new Uint8Array([1, 0, 0, 0, 0, 9]))).toThrow();
  });
});
