# Decisions

What was taken from other clients, what was left out, and why — so a choice
that looks like an omission can be told from one that was made. Each entry
says what it rests on: a measurement, a reading of the source, or the
platform's documentation. Newest first within each section.

## Taken

**Streams numbered and chained as each browser does them** (2026-10-18).
Watched with `scripts/capture-frames.ts`, a proxy logging every frame Chrome
155, Edge 154 and Firefox 158 sent while loading the same page. Chromium
makes a stream depend, exclusively, on the newest one still open at its
priority or above, and on none otherwise, so requests at once form a chain.
Firefox starts at stream 3, depends on none, and sends each stream a
WINDOW_UPDATE of 12,451,840 in the same write as its HEADERS. We sent stream
1 for every profile, which tls.peet.ws shows. curl-impersonate, which impers
wraps, keeps only Firefox's old PRIORITY tree and starts at 1 as well. The
Firefox values are applied to the older Firefox and Tor profiles by
inference: they open with the same SETTINGS and no PRIORITY frames, but were
not watched themselves. The WAF benchmark did not move for it: Firefox
passed 16 of 22 before and after.

**`onRedirect`** (2026-10-18), shaped after httpcloak's, read in its source
(`transport/transport.go`) rather than its readme: asked before each hop,
`false` returns the 3xx, read-only so it cannot get round the credentials
dropped across hosts, and not asked about a hop past `maxRedirects`.

**`timingOf`** (2026-10-18), with only what was read off the clock. httpcloak's
own `Timing` notes that it once filled DNS, TCP and TLS as fixed shares of the
first byte. Phases that did not happen are left out, not zeroed.

**`ca`, `verify: false`, `clientCert`** (2026-10-18). `ca` replaces the web
roots, as curl's `--cacert` and Node's `ca` do; `verify: false` still checks
the handshake signature, as `curl -k` does. They live in the ticket store,
because rustls resumes a ticket only under the verifier that earned it.

**Connections kept per session** (2026-10-18). Measured on the deployed
Worker: 60 requests in one invocation took 1 connection and all answered;
without reuse, 50 answered before "Too many subrequests".

**Session state, after httpcloak** (2026-09-25): cookies, TLS tickets and
the profile, restored only as the same browser — httpcloak refuses a state
whose TLS settings changed, and so do we.

## Left out

**httpcloak's `OnPreRequest` and `OnPostResponse`** (2026-10-18). Wrapping
`session.fetch` does the same, and a hook rewriting a request after its
headers are placed could undo the browser's order.

**What Edge does with images** (2026-10-18). It sends them at a low weight
and raises them with PRIORITY frames once the page has laid them out. That
is the renderer's doing; a client fetching no images has nothing to raise.

**A second connection for subresources** (2026-10-18). Chrome and Edge each
opened a second connection to the same origin partway through the page, but
not for the same requests, and no rule was found to copy.

**VPN Gate as a way round the Cloudflare block** (2026-10-05). Its servers
speak OpenVPN, SSTP and L2TP, which carry IP packets, not TCP streams: a
Worker would need an OpenVPN client and a TCP/IP stack of its own in
WebAssembly under the TLS it already does. Its addresses are also on public
blocklists, which defeats the point of impersonating a browser. A SOCKS or
HTTP proxy does the same job with what is already here.

**Compatibility flags** (2026-10-05). None lifts the block on sockets to
Cloudflare's addresses. `cots_on_external_fetch` is about which CAs the
platform's `fetch()` trusts; `connect_pass_through` is for outbound Workers.
The block is in Cloudflare's network, not in workerd, which is why
`wrangler dev` never shows it.

**httpcloak's cross-domain warming** (2026-09-25). Its readme warms a session
on one site to use on another; TLS tickets are keyed by hostname, so a
ticket from one site is never offered to another.

**A flat 24-hour ticket lifetime** (2026-09-25), as httpcloak sets. A ticket
keeps the lifetime its server gave it, up to the 7 days TLS 1.3 allows.

**A proxy's credentials in a saved session** (2026-09-25), which httpcloak's
blob carries. The proxy, `ca` and a client key are given again on restore.

**Early data** (2026-09-25). httpcloak's docs call resumption "0-RTT"; Chrome
sends no early data on a resumed connection, and neither do we.

**The Kyber draft group, 0x6399** (2026-09-26), which Chrome 124–130 sent.
rustls has no implementation, and naming a group without its key share
makes servers answer with a HelloRetryRequest.

**HTTP/3, a TCP/IP fingerprint, binding a local address**. A Worker has no
UDP, and the runtime owns the socket below TLS.

## Found along the way

- tls.peet.ws closes every connection after one answer, so it can never
  show connection reuse; count dials instead (`/reuse` in `dev/reuse.ts`).
- aircanada.com (Akamai) answers the same build with a sensor page one
  request and the real page the next: a miss there is not a regression until
  the previous build, run alongside, passes where this one fails.
- Firefox trails Chrome on the WAF benchmark for a reason that is still not
  known: not ML-KEM (2026-09-26), not the stream numbering (2026-10-18).
