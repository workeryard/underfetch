/**
 * A session's state, kept past the isolate that made it.
 *
 * A Worker has no file to save to, and which store fits is the caller's
 * business: a Durable Object keeps the object itself, KV or D1 a string. So
 * `state()` gives a plain object and `marshal()` the same as JSON; where it
 * goes is up to whoever calls them.
 *
 * What is kept is the identity: which browser, its cookies, and its TLS
 * tickets. What is not is infrastructure — the proxy and its password,
 * timeouts, headers — which the caller hands `unmarshal` again, so a saved
 * state never carries a proxy's credentials.
 *
 * Cookies and tickets log you in and resume sessions: keep the state as a
 * password is kept.
 */

import type { Cookie } from '../client/cookies';
import { withFingerprints, type Fingerprints } from '../fingerprint/custom';
import type { Impersonation } from '../fingerprint/profiles';

/** Bumped on any change to the shape; a newer state is refused, not misread. */
export const STATE_VERSION = 1;

export interface SessionState {
  version: number;
  /** Unix milliseconds. */
  savedAt: number;
  /**
   * The browser the tickets and cookies were earned as. Null when nothing was
   * impersonated.
   */
  impersonate: Identity | null;
  /** Null when the session kept no cookies. */
  cookies: Cookie[] | null;
  /** TLS 1.3 tickets, base64: what `TicketStore.export` wrote. Empty when none. */
  tickets: string;
}

/**
 * Enough to rebuild a profile and to know it again: the built-in it started
 * from and the strings it was given, then the fingerprints it claimed.
 */
export interface Identity {
  /** The built-in profile's name, when it began as one. */
  name?: string | undefined;
  /** The JA3 and Akamai strings given with it; see `withFingerprints`. */
  input?: Fingerprints | undefined;
  ja4?: string | undefined;
  ja3?: string | undefined;
  akamai?: string | undefined;
}

export class SessionStateError extends Error {
  override name = 'SessionStateError';
}

export function toBase64(bytes: Uint8Array): string {
  let text = '';
  // In pieces: spreading a large array into one call overflows the stack.
  for (let at = 0; at < bytes.length; at += 0x8000) {
    text += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return btoa(text);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Reads a state given as an object or as `marshal()`'s JSON, or says why not. */
export function readState(input: SessionState | string): SessionState {
  let state: unknown;
  try {
    state = typeof input === 'string' ? JSON.parse(input) : input;
  } catch {
    throw new SessionStateError('the saved session is not JSON');
  }
  if (typeof state !== 'object' || state === null) {
    throw new SessionStateError('the saved session is not an object');
  }
  const s = state as Partial<SessionState>;
  if (typeof s.version !== 'number') {
    throw new SessionStateError('the saved session names no version');
  }
  if (s.version > STATE_VERSION) {
    throw new SessionStateError(
      `the saved session is version ${s.version}, newer than this build reads (${STATE_VERSION})`,
    );
  }
  const identity = s.impersonate;
  const claims = (i: Identity) =>
    [i.ja4, i.ja3, i.akamai].some((claim) => typeof claim === 'string');
  if (
    identity !== null &&
    (typeof identity !== 'object' || identity === undefined || !claims(identity))
  ) {
    throw new SessionStateError('the saved session does not say what it impersonated');
  }
  if (s.cookies !== null && !Array.isArray(s.cookies)) {
    throw new SessionStateError('the saved cookies are not a list');
  }
  if (typeof s.tickets !== 'string') {
    throw new SessionStateError('the saved tickets are not a string');
  }
  return {
    version: s.version,
    savedAt: typeof s.savedAt === 'number' ? s.savedAt : 0,
    impersonate: identity,
    cookies: s.cookies ?? null,
    tickets: s.tickets,
  };
}

/** What `profile` claims, as an identity records it. */
export function identityOf(
  profile: Impersonation,
  name: string | undefined,
  input: Fingerprints | undefined,
): Identity {
  const { ja4, ja3, akamai } = profile.expected;
  return {
    ...(name === undefined ? {} : { name }),
    ...(input === undefined ? {} : { input }),
    ...(ja4 === undefined ? {} : { ja4 }),
    ...(ja3 === undefined ? {} : { ja3 }),
    akamai,
  };
}

/**
 * The profile to restore as: the one `given`, or else the one the state
 * names, rebuilt from its strings. A state earned as one browser is refused
 * as another — its tickets and cookies behind a different handshake are
 * exactly the mismatch a bot check looks for — so every fingerprint the state
 * recorded must be the restored profile's too. Aliases are the same browser,
 * so the comparison is by fingerprint, not by name.
 */
export function restoredProfile(
  saved: Identity | null,
  given: Impersonation | undefined,
  named: (name: string) => Impersonation | undefined,
  /**
   * Every built-in profile, oldest first. A short name such as `firefox`
   * moves to a newer browser over time; a state saved under it is restored
   * as the browser it was earned as, found by its fingerprints, rather than
   * refused. Versions can share every fingerprint and differ only in their
   * user-agent, so of those the newest is taken: a short name always pointed
   * at the newest when the state was saved.
   */
  builtIn: Iterable<Impersonation> = [],
): Impersonation | undefined {
  if (saved === null) {
    if (given !== undefined) {
      throw new SessionStateError(
        'the session was saved without a profile; restore it without one',
      );
    }
    return undefined;
  }
  let profile = given ?? rebuilt(saved, named);
  if (given === undefined && saved.input === undefined && !matches(saved, profile)) {
    profile = [...builtIn].reverse().find((candidate) => matches(saved, candidate)) ?? profile;
  }
  if (profile === undefined) {
    throw new SessionStateError(
      'the session was saved with a profile of your own; pass it again to restore',
    );
  }
  for (const claim of ['ja4', 'ja3', 'akamai'] as const) {
    const was = saved[claim];
    if (was !== undefined && profile.expected[claim] !== was) {
      throw new SessionStateError(
        `the session was saved as ${saved.name ?? was}, and this profile's ${claim} is ` +
          `${profile.expected[claim] ?? 'not stated'}, not ${was}`,
      );
    }
  }
  return profile;
}

/** Whether every fingerprint the state recorded is `profile`'s too. */
function matches(saved: Identity, profile: Impersonation | undefined): boolean {
  if (profile === undefined) return false;
  return (['ja4', 'ja3', 'akamai'] as const).every(
    (claim) => saved[claim] === undefined || profile.expected[claim] === saved[claim],
  );
}

function rebuilt(
  saved: Identity,
  named: (name: string) => Impersonation | undefined,
): Impersonation | undefined {
  const base = saved.name === undefined ? undefined : named(saved.name);
  if (base === undefined || saved.input === undefined) return base;
  try {
    return withFingerprints(base, saved.input);
  } catch (error) {
    throw new SessionStateError(`the saved fingerprints could not be rebuilt: ${String(error)}`);
  }
}
