/**
 * What a request says it is when nobody said otherwise: a profile brings a
 * browser's, a caller may set their own. Some servers refuse a request with
 * none at all — Reddit answers 403 — so a plain one names this library, the
 * way curl names itself, rather than pretending to be a browser.
 */
export const USER_AGENT = 'underfetch/0.1';
