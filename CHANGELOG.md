# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
[Semantic Versioning](https://semver.org/) — until 1.0.0, a minor version may
change the API.

## 0.1.0 — unreleased

The first release.

### Connections

- HTTP over the Worker's own `connect()`, without the `cf-*` headers `fetch()`
  adds.
- SOCKS5 with username and password, SOCKS4 and 4a, and HTTP `CONNECT`, in
  the clear or over TLS to the proxy. The target's name is resolved at the
  proxy.
- TLS 1.2 and 1.3 by rustls in WebAssembly, certificates checked against the
  target's name. Short chains are completed from AIA, as browsers do.
- `ca` to trust a private CA instead of the web's roots, `verify: false` for
  a server under test, and `clientCert` for mutual TLS.
- HTTP/1.1 and HTTP/2 as ALPN decides, with HPACK and flow control both ways.
- Connections kept per session: one HTTP/2 connection per origin carries
  every request to it, HTTP/1.1 is reused once an answer is read, and an idle
  connection closes after `idleTimeoutMs`. `close()`, `using` and
  `await using` let them go.
- Sites behind Cloudflare, which a Worker's socket may not reach, fail at
  once with a `DialError` that says so; `onCloudflare: 'fetch'` sends them
  through the Worker's own `fetch()` instead, marked as not impersonated.

### Browsers

- 39 browser profiles under impers' names: 35 from curl-impersonate's
  captures, and Chrome 155, Edge 155, Brave 154 and Firefox 158 recorded from
  the browsers themselves. `chrome`, `edge`, `brave`, `firefox`, `safari`,
  `safari_ios`, `chrome_android` and `tor` name the newest of each.
- Each profile's JA4 and Akamai fingerprint match the browser's, checked
  offline in the tests and live against tls.peet.ws: ciphers, extensions and
  their order, GREASE, key shares with X25519MLKEM768, padding, ALPS, GREASE
  ECH, HTTP/2 settings, window, priorities and stream numbering.
- Headers in the browser's order, for a page load or a script's `fetch()`,
  measured from Chrome, Edge, Brave and Firefox.
- A profile from a JA3 and an Akamai string, with `ja3` and `akamai`.

### Requests

- Redirects with credentials dropped across hosts, and `onRedirect` to stop
  one before it is followed.
- Cookies, retries of what is safe to retry, timeouts and `AbortSignal`, and
  a deadline for connecting alone.
- Basic, Bearer and Digest authentication.
- gzip, deflate, brotli and zstd undone; streamed uploads and responses.
- `timingOf(response)`: connecting, the proxy, TLS, the first byte and the
  whole body, as measured.
- WebSocket over its own connection, with permessage-deflate.
- A session's browser, cookies and TLS tickets saved with `state()` or
  `marshal()` and carried on in another isolate with `Session.unmarshal()`.
