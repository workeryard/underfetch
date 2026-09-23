/**
 * Handshake failures a second connection can fix. The TLS module reports
 * errors as strings, so they are recognised by what they say.
 */

/** The server sent a chain short of its issuer; see `aia.ts`. */
export const missingIssuer = (error: unknown) => String(error).includes('UnknownIssuer');

/**
 * The server signed with a scheme we offered but cannot check. A browser
 * offers SHA-1 and ECDSA with SHA-512, which the verifier has no code for, and
 * an old TLS 1.2 server that prefers SHA-512 will pick it.
 */
export const unverifiableSignature = (error: unknown) =>
  String(error).includes('SignedHandshakeWithUnadvertisedSigScheme');
