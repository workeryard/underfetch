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
import type { Impersonation } from '../fingerprint/profiles';

/** Bumped on any change to the shape; a newer state is refused, not misread. */
export const STATE_VERSION = 1;

export interface SessionState {
  version: number;
  /** Unix milliseconds. */
  savedAt: number;
  /**
   * The browser the tickets and cookies were earned as, by its expected JA4
   * and, for a built-in, its name. Null when nothing was impersonated.
   */
  impersonate: { name?: string | undefined; ja4: string } | null;
  /** Null when the session kept no cookies. */
  cookies: Cookie[] | null;
  /** TLS 1.3 tickets, base64: what `TicketStore.export` wrote. Empty when none. */
  tickets: string;
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
  if (
    identity !== null &&
    (typeof identity !== 'object' || identity === undefined || typeof identity.ja4 !== 'string')
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

/**
 * The profile to restore as. A state earned as one browser is refused under
 * another: its tickets and cookies with a different handshake are exactly
 * the mismatch a bot check looks for. Aliases are the same browser, so the
 * comparison is by JA4, not by name.
 */
export function restoredProfile(
  saved: SessionState['impersonate'],
  given: Impersonation | undefined,
  named: (name: string) => Impersonation | undefined,
): Impersonation | undefined {
  if (saved === null) {
    if (given !== undefined) {
      throw new SessionStateError(
        'the session was saved without a profile; restore it without one',
      );
    }
    return undefined;
  }
  const profile = given ?? (saved.name === undefined ? undefined : named(saved.name));
  if (profile === undefined) {
    throw new SessionStateError(
      `the session was saved with a profile of your own (${saved.ja4}); pass it again to restore`,
    );
  }
  if (profile.expected.ja4 !== saved.ja4) {
    throw new SessionStateError(
      `the session was saved as ${saved.name ?? saved.ja4}, not as ${profile.expected.ja4}`,
    );
  }
  return profile;
}
