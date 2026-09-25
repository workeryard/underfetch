/**
 * The runtime-free core: everything but the Cloudflare adapter, which lives
 * in `underfetch/workers`. Supply a `Dial` and a `TlsFactory` and it runs
 * anywhere, which is also how the tests run it.
 *
 *   client/       what a caller uses: fetch, sessions, redirects, retries, cookies
 *   http/         HTTP/1.1 and HTTP/2 over a socket we opened
 *   tls/          driving TLS over that socket; rustls in WebAssembly
 *   net/          sockets and the proxy handshakes, SOCKS5 and CONNECT
 *   fingerprint/  what a browser sends, and proving that we send it
 */

export { aborted, deadline, TimeoutError, until } from './client/abort';
export { CookieJar } from './client/cookies';
export type { Cookie } from './client/cookies';
export { fetchOver } from './client/fetch';
export type { FetchOverOptions } from './client/fetch';
export { followRedirects } from './client/redirects';
export type { RedirectOptions } from './client/redirects';
export { ApiError, buildRequest } from './client/request';
export type { BodyOptions, Params } from './client/request';
export { withRetry } from './client/retry';
export type { RetryOptions } from './client/retry';
export { Session } from './client/session';
export type {
  SessionDefaults,
  SessionOptions,
  SessionRequestInit,
  SessionWebSocketInit,
} from './client/session';
export { connectWebSocket, WebSocketRefused } from './client/websocket';
export type { WebSocketConnectOptions, WebSocketOptions } from './client/websocket';
export { WebSocketConnection, WebSocketError } from './http/websocket';
export type { WebSocketClose, WebSocketMessage } from './http/websocket';

export { DEFAULT_PROFILE, http2Fetch } from './http/h2/connection';
export type { Http2Profile } from './http/h2/connection';
export { Http2Error } from './http/h2/frames';
export { Http1Error, http1Fetch } from './http/http1';
export { acceptable, decompressed, zlibDecoders } from './http/decompress';
export type { Decoders, ZlibModule } from './http/decompress';
export { zlibInflater } from './http/permessage-deflate';
export type { InflaterFactory, InflateModule, MessageInflater } from './http/permessage-deflate';
export { USER_AGENT } from './http/user-agent';

export { TlsError, tlsTunnel } from './tls/tunnel';
export type { TlsFactory, TlsSession } from './tls/tunnel';

export { ByteReader, ByteWriter } from './net/bytes';
export { HttpConnectError, httpConnect } from './net/http-connect';
export { tunnelThrough } from './net/proxy';
export { DialError } from './net/socket';
export type {
  ByteSocket,
  Dial,
  HttpProxy,
  HttpsProxy,
  Proxy,
  Socks4Proxy,
  Socks5Proxy,
} from './net/socket';
export { Socks4Error, socks4Connect } from './net/socks4';
export { Socks5Error, socks5Connect } from './net/socks5';

export { encodeExtensions, GREASE, profiles } from './fingerprint/profiles';
export {
  arrange,
  headerOrder,
  requestOrder,
  ResourceError,
  resourceHeaders,
} from './fingerprint/order';
export { blinkHash, blinkTableOrder } from './fingerprint/blink-order';
export type { Family, FetchSite, Resource } from './fingerprint/order';
export { FingerprintError, fromFingerprints } from './fingerprint/custom';
export type { FromFingerprints } from './fingerprint/custom';
export type { Extension, Impersonation, ProfileName } from './fingerprint/profiles';
export {
  akamai,
  ja3,
  ja4,
  parseClientHello,
  verifyProfile,
  VerifyError,
} from './fingerprint/verify';
export type { ClientHello, Verdict } from './fingerprint/verify';
