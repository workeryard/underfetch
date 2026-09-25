# underfetch

HTTP over raw sockets for Cloudflare Workers: SOCKS5, SOCKS4 and HTTP(S)
`CONNECT` proxies, TLS in WebAssembly, HTTP/1.1 and HTTP/2, and a handshake that can look
like Chrome, Firefox or Safari.

It is built for leaving **through a proxy**, and that is where all of it works.
Without one it reaches any site not served through Cloudflare; a site that is
cannot be reached from a Worker's socket at all — see below.

```ts
import { Session } from 'underfetch/workers';

const session = new Session({
  proxy: { kind: 'socks5', hostname: '203.0.113.7', port: 1080 },
});

const response = await session.fetch('https://api.example.com/v1/models');
```

## Why it exists

A Worker's `fetch()` cannot be pointed at a proxy, cannot ride a socket you
opened yourself, and adds `cf-connecting-ip`, `cf-ray` and friends to every
outbound request. `cloudflare:sockets` gives you a TCP socket, but nothing
above it — so everything from the proxy handshake upwards has to be written by
hand. That is what this is.

The proxy is optional. Without one, requests still leave off a raw socket
rather than through `fetch`, which is enough to drop the `cf-*` headers.

**But not to a site behind Cloudflare.** A deployed Worker may not open a TCP
socket to Cloudflare's own IP ranges — [the platform blocks
it](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) — and
that is where every site served through Cloudflare lives, `example.com`
included. Such a request fails at once with a `DialError` that says so, and is
not retried; through a proxy it works, since the socket then goes to the
proxy. `wrangler dev` does not enforce the block, so only a deployment shows
it. Measured from a deployed Worker on 2026-09-25: every case in the live
matrix passes but the seven whose target is on Cloudflare. Through free
public proxies, the ones still alive reached `example.com` as often as they
reached a site elsewhere.

Without a proxy, such a site can still be reached, just not by underfetch:

```ts
const session = new Session({ impersonate: 'chrome', onCloudflare: 'fetch' });
const response = await session.get('https://example.com/');
response.headers.get('x-underfetch-via'); // 'fallback'
```

`onCloudflare: 'fetch'` sends a request refused this way through the Worker's
own `fetch()`. It arrives, with the profile's headers, but over Cloudflare's
TLS rather than the profile's, with Cloudflare's own headers added, and with
`accept-encoding` rewritten to `gzip, br` — so its answer says
`x-underfetch-via: fallback`, and nothing claims it was impersonated. Redirects
and cookies still go through the session. It is off by default, a WebSocket is
never sent this way, and with a proxy it never happens.

Two more limits come from the platform rather than from here. Each connection
counts against the subrequests one invocation may make — a redirect, a retry,
a fetched intermediate and a WebSocket each open one — so a Worker making many
requests per invocation runs out sooner than it would with `fetch`, which
reuses connections. And requests leave from Cloudflare's addresses unless a
proxy says otherwise; some sites limit those (Google answered 429).

## Why TLS is done here

`connect()` reaches a proxy, and `startTls({ expectedServerHostname })` looks
like it would finish the job — dial the proxy, then verify the certificate
against the real target. It does not. workerd logs that option as unsupported
and carries an autogate that turns the call into a `TypeError`:

```cpp
// workerd/api/sockets.c++
if (opts.expectedServerHostname != kj::none) {
  if (util::Autogate::isEnabled(AutogateKey::STARTTLS_REJECT_EXPECTED_SERVER_HOSTNAME)) {
    JSG_FAIL_REQUIRE(TypeError,
        "The expectedServerHostname option is not currently supported in startTls.");
  } else {
    LOG_ERROR_PERIODICALLY("NOSENTRY startTls called with unsupported expectedServerHostname option");
  }
}
```

An autogate is a switch Cloudflare flips centrally, so the option can stop
working without any release of yours. It is off in `wrangler dev`, which is why
local testing proves nothing. So the certificate is checked here instead, by
rustls compiled to WebAssembly (613 KB, 289 KB gzipped, committed — building it
needs Rust, using it does not).

## Install

It is not on npm yet. Depend on a checkout instead:

```
pnpm add link:../underfetch
```

Your `wrangler.jsonc` needs the WebAssembly rule:

```jsonc
{
  "rules": [{ "type": "CompiledWasm", "globs": ["**/*.wasm"], "fallback": true }],
}
```

## Using it

```ts
import { Session } from 'underfetch/workers';

// No proxy: straight off a socket, without the cf-* headers.
const direct = new Session();

// Through a SOCKS5 proxy, with credentials and a deadline.
const viaSocks = new Session({
  proxy: {
    kind: 'socks5',
    hostname: '203.0.113.7',
    port: 1080,
    username: 'ada',
    password: 'lovelace',
  },
  timeoutMs: 30_000,
  headers: { 'user-agent': 'my-worker/1.0' },
});

// Through an HTTP CONNECT proxy instead.
const viaHttp = new Session({
  proxy: { kind: 'http', hostname: 'proxy.internal', port: 8080 },
});

// The same over TLS: the proxy's certificate is checked against its name,
// and the target's TLS runs inside that connection.
const viaHttps = new Session({
  proxy: { kind: 'https', hostname: 'proxy.example.com', port: 443 },
});

// SOCKS4, as 4a: the proxy resolves the name. `username` is the user ID.
const viaSocks4 = new Session({
  proxy: { kind: 'socks4', hostname: '203.0.113.9', port: 1080 },
});

// One request may override the session: `null` forces it direct.
await viaSocks.fetch('https://example.com/', { proxy: null });
```

### Shorter forms

A session can hold the host, and there is a method per verb:

```ts
const api = new Session({
  baseUrl: 'https://api.example.com',
  impersonate: 'chrome',
  headers: { 'user-agent': 'my-worker/1.0' },
});

await api.get('/v1/models', { params: { limit: 20 } });
await api.post('/v1/chat/completions', { json: { model: 'x', messages } });
await api.del('/v1/files/abc');
```

For one request, skip the session:

```ts
import { get, post, request } from 'underfetch/workers';

await get('https://api.example.com/v1/models', { impersonate: 'chrome' });
await post('https://api.example.com/token', { form: { grant_type: 'client_credentials' } });
await request('PATCH', url, { json: { name: 'new' } });
```

| option                           | what it does                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------- |
| `params`                         | query parameters, merged with any already in the URL                         |
| `json`                           | a JSON body, and the `content-type` that implies                             |
| `form`                           | an `application/x-www-form-urlencoded` body                                  |
| `auth`                           | `{ bearer }`, or `{ username, password }` as Basic, or with `type: 'digest'` |
| `headers`                        | as `fetch` takes them                                                        |
| `proxy`                          | overrides the session's; `null` forces this one direct                       |
| `timeoutMs`                      | gives up, headers and body together                                          |
| `connectTimeoutMs`               | gives up on dialling, the proxy and TLS alone                                |
| `allowRedirects`, `maxRedirects` | default `true` and `20`                                                      |
| `retry`                          | a count, `RetryOptions`, or `false`                                          |
| `impersonate`                    | whose ClientHello to send                                                    |

What comes back is a plain `Response`, deliberately. It already carries
`status`, `headers`, `text()` and `json()`, and unlike a bespoke response
object it leaves the body **streaming** — server-sent events arrive event by
event, and nothing waits for the whole answer. After redirects, `response.url`
is where the chain ended.

A `FormData` body goes out as `multipart/form-data`, files and all. Its
boundary is the runtime's own format, not the browser's
`----WebKitFormBoundary…`, which a server that looks can tell apart.

`connectTimeoutMs` bounds only the connecting — dialling, the proxy's
handshake and TLS — so a dead proxy fails in a second or two and a retry
still has time, where `timeoutMs` alone would wait out the whole budget on it.

A redirect that changes host drops `authorization` and `cookie`.

Digest answers the server's challenge, as curl does: the request goes once
without credentials, and again with them after the 401 — so it costs a round
trip, and a streamed body gets the 401 back rather than a second send. MD5,
SHA-256 and their `-sess` forms are spoken; SHA-512-256 and `qop=auth-int`
are refused by name. Digest credentials stay with the host they were given
for, across redirects too.

A body given as a `ReadableStream` is **uploaded as it arrives** and never held
whole in memory — chunked on HTTP/1.1, frame by frame on HTTP/2 — so a Worker
can pass on an upload larger than it could hold:

```ts
await session.post(url, { body: request.body, headers: { 'content-type': type } });
```

The price is that it can be sent only once. A 307 or 308, which would repeat
it, comes back to you rather than being followed, and it is never retried.
Any other body — a string, `json`, `form`, bytes — is already in memory, goes
out with a `Content-Length`, and is repeated freely.

### Cookies

A session can keep them, and a jar is always something the caller holds — one
isolate serves many requests, and a jar shared by accident would hand one user
another's session.

```ts
const session = new Session({ cookies: true });
await session.post('https://api.example.com/login', { json: { user, password } });
await session.get('https://api.example.com/me'); // carries what login set

session.cookies?.all(); // or pass your own CookieJar in to share it
```

Domain, path, `Secure`, `Max-Age` and `Expires` are all honoured, including a
server deleting a cookie by dating it in the past. A cookie set partway through
a redirect is picked up on the next hop.

### WebSocket

```ts
const ws = await session.websocket('wss://stream.example.com/live', {
  headers: { origin: 'https://example.com' },
  protocols: ['graphql-ws'],
});

await ws.send(JSON.stringify({ subscribe: 'prices' }));
for await (const message of ws) {
  if (message.type === 'text') console.log(message.data);
}
console.log(ws.closed); // { code, reason }
```

It is read by asking, as impers has it: `recv()` gives the next message, or
`null` once the connection has closed, and the socket is also an async
iterator. Nothing runs unless something awaits it, which is what a Worker
wants. Pings are answered as they pass, a close from the server is answered,
and `close()` waits up to five seconds for the server to agree. A server that
will not upgrade throws `WebSocketRefused` with its status and headers.

It goes out as Chrome's does — on a connection of its own, with ALPN
`http/1.1` alone, since HTTP/2 has no Upgrade — so the JA4 there ends `h1`
where the page's ends `h2`, with both hashes the same. The session's proxy,
cookies and headers come along, less those a browser sends only when it
navigates (`accept`, `sec-fetch-*`, `sec-ch-ua*` and the like). The order
is Chrome's, written from its known handshake rather than from a capture;
`origin` is sent only when given.

`permessage-deflate` is offered as Chrome offers it, word for word, where the
Worker can read it: a message compressed with the server's window carried
over needs an inflater flushed at every message, which `DecompressionStream`
cannot do, so it comes from `node:zlib` — the same recent compatibility date
as brotli. On an older date it is not offered, and servers send plain.
Messages we send go uncompressed, which the RFC allows; `ws.compressed` says
whether the server may compress.

A message over `maxMessageBytes` (16 MiB by default) closes the connection
with 1009, text that is not UTF-8 with 1007, and a broken frame with 1002.

### Saving a session

A session's identity — which browser, its cookies, its TLS tickets — can
outlive the isolate that earned it. A Worker has no file to save to, and
which store fits is yours to choose, so there are two shapes of the same
thing:

```ts
// A Durable Object keeps the object as it is.
await this.ctx.storage.put('session', session.state());
const again = Session.unmarshal(await this.ctx.storage.get('session'), { proxy });

// KV, D1, R2 or anything else keeps the string.
await env.KV.put(`session:${user}`, session.marshal());
const later = Session.unmarshal(await env.KV.get(`session:${user}`), { proxy });
```

The first request of the restored session resumes TLS with a ticket the
saved one was given and carries its cookies — in another isolate, after a
deploy. Only TLS 1.3 tickets are kept, and without the server's certificate
chain, which resuming does not need; a saved session is usually well under
a kilobyte.

What is saved is the identity, not the plumbing: the proxy and its
password, timeouts and headers are given to `unmarshal` again, so a saved
state never carries a proxy's credentials. A state saved as one browser is
refused as another — its tickets and cookies behind a different handshake
are the mismatch a bot check looks for — and one saved with a profile of
your own needs that profile passed again. A state from a newer build is
refused rather than misread.

**A saved session logs in and resumes: keep it as a password is kept.**

### Retries

Off the shelf, two extra attempts on 408, 429 and the 5xx that mean _later_,
plus anything that failed to connect at all. Backoff is exponential with
jitter, and `Retry-After` is obeyed up to a ceiling.

```ts
new Session({ retry: { limit: 3, maxDelayMs: 10_000 } });
await session.post(url, { json: body, retry: { methods: ['POST'] } });
```

**A POST is never repeated by default.** Only methods defined to be idempotent
are, because repeating a request that changed something may change it twice.
Say `methods: ['POST']` when you know it is safe. An `AbortError` is never
retried either: that is the caller changing their mind, not a failure.

### Without the Workers adapter

The protocol layer names no runtime. Supply your own socket and TLS and it runs
anywhere — which is also how the test suite covers it, against in-memory
streams rather than a network:

```ts
import { fetchOver } from 'underfetch';

await fetchOver(request, { dial, tls, proxy });
```

`dial` opens a TCP connection and returns `{ readable, writable, close }`.
`tls` returns a session with `receive`, `outgoing`, `send`, `plaintext`,
`handshaking` and `close` — a sans-I/O state machine, so swapping in a
different TLS stack means implementing six methods.

## What it does and does not do

|                                                  |                                |
| ------------------------------------------------ | ------------------------------ |
| SOCKS5, with username/password auth              | yes                            |
| SOCKS4 and 4a                                    | yes, no IPv6 targets           |
| HTTP `CONNECT`, with basic auth                  | yes                            |
| HTTP `CONNECT` over TLS to the proxy             | yes, its certificate checked   |
| TLS 1.2 and 1.3, certificates verified           | yes                            |
| Short certificate chains completed from AIA      | yes, as browsers do            |
| Streaming request and response bodies            | yes                            |
| gzip, deflate, brotli and zstd, undone for you   | yes, see below                 |
| Timeouts and `AbortSignal`                       | yes                            |
| Redirects, with credentials dropped across hosts | yes                            |
| HTTP/2, with HPACK and flow control              | yes                            |
| Browser impersonation, TLS and HTTP/2            | 35 browsers, see below         |
| Cookies, with domain and path scoping            | yes                            |
| Retries, idempotent methods only by default      | yes                            |
| Basic, Bearer and Digest authentication          | yes, Digest in MD5 and SHA-256 |
| WebSocket, over its own `http/1.1` connection    | yes, with permessage-deflate   |
| HTTP/3                                           | never — a Worker has no UDP    |

The target hostname is sent to the proxy as a name, not an address, so DNS is
resolved at the proxy rather than leaking from the Worker.

## The fingerprint

A stock rustls ClientHello is recognisable at a glance: it sends no GREASE, and
nothing else on the web omits it. Ask for a browser instead:

```ts
const session = new Session({ impersonate: 'chrome' });
```

Thirty-five browsers are built in, under the names impers gives them, and
both fingerprints a server reads match the real browser for each — JA4 from
the handshake, and the Akamai string from the HTTP/2 settings:

| family         | profiles                                                                                                                                                                                        |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chrome         | `chrome99` `chrome100` `chrome101` `chrome104` `chrome107` `chrome110` `chrome116` `chrome119` `chrome120` `chrome123` `chrome124` `chrome131` `chrome133a` `chrome136` `chrome142` `chrome150` |
| Chrome Android | `chrome99_android` `chrome131_android`                                                                                                                                                          |
| Edge           | `edge99` `edge101`                                                                                                                                                                              |
| Firefox        | `firefox133` `firefox135` `firefox144`                                                                                                                                                          |
| Safari         | `safari153` `safari155` `safari170` `safari180` `safari184` `safari260` `safari2601`                                                                                                            |
| Safari iOS     | `safari172_ios` `safari180_ios` `safari184_ios` `safari260_ios`                                                                                                                                 |
| Tor            | `tor145`                                                                                                                                                                                        |

`chrome`, `chrome_android`, `edge`, `firefox`, `safari`, `safari_ios` and
`tor` name the newest of each. The defaults, for instance:

| profile   | JA4                                    | Akamai                                                 |
| --------- | -------------------------------------- | ------------------------------------------------------ |
| `chrome`  | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `firefox` | `t13d1717h2_5b57614c22b0_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s`   |
| `safari`  | `t13d2013h2_a09f3c656075_7f0f34a4126d` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p`        |

Chrome GREASEs and shuffles its extensions, Firefox does neither, Safari
GREASEs but keeps a fixed order.

A profile also carries the browser's **request headers, written in the
browser's order** — `user-agent`, `accept`, `sec-ch-ua`, `sec-fetch-*` and the
rest — because a handshake that matches Chrome while the headers say "not a
browser" fools nobody. Headers a session or a request sets win over the
profile's, and take the slot the browser gives them: `content-length`,
`content-type`, `origin`, `referer`, `cookie` and the others each go where
that browser puts them. (`Headers` sorts its names, so this has to be done on
the wire; until it was, every request went out alphabetically.)

The orders were measured, not written from memory: Edge 153, Chrome 154 and
Firefox 153 pointed at a local HTTP/2 server that recorded every request's raw header
order and stream weight (`scripts/capture-headers.ts`). Each navigation order
agrees with the capture the profiles came from, and Chrome 154 wrote every
request exactly as Edge 153 did.

Chromium has no one place for a fetch()'s own headers — `authorization`,
`x-api-key` and the like. Blink keeps them in a hash table with
`user-agent` and the `sec-ch-ua` hints and writes them out in table order,
so where each lands depends on every name in the set. That table is
reproduced here from Chromium's source — its rapidhash-based case-folding
hash, its sizing and its probing — and checked against the browser: it gives
the order Chrome 154 wrote for every one of 55 captured sets, 40 of them random
sets of one to twelve headers predicted before they were captured. Firefox is
simpler: a page's own headers go after `referer`.

No Safari has been measured beyond its page load, so a Safari profile keeps
its captured order and puts anything else after it.

A browser sends an API call differently from a page load, and the request can
say which it is:

```ts
await session.get('https://api.example.com/v1/me', {
  resource: 'fetch', // what a page's script sends: fetch() or XHR
  site: 'same-site', // where the page stands; default same-origin
  headers: { authorization: `Bearer ${token}` },
});
```

A `fetch` goes out as that browser's fetch() does, as measured: `accept: */*`,
`sec-fetch-mode: cors`, `sec-fetch-dest: empty`, no `upgrade-insecure-requests`
or `sec-fetch-user`, Chromium's own order for it, and the browser's lower
priority — `u=1, i` and weight 220 for Chromium, `u=4` and weight 22 for
Firefox. Safari refuses it with a `ResourceError`: nothing has been measured
to imitate. The default, `document`, is a page load.

`accept-encoding` is the browser's too — `gzip, deflate, br, zstd` for Chrome
— wherever the answer can be read. `DecompressionStream` has only gzip and
deflate, so brotli and zstd come from the Worker's own `node:zlib`, which a
recent compatibility date carries (`2026-09-21` does, `2024-06-01` does not)
without `nodejs_compat`. On an older date they are cut from the header rather
than offered: asking for an answer that cannot be decoded is how a request
breaks.

Where it cannot be the browser, it says so. The `sec-ch-ua` brand list rotates between
Chrome releases, so check it against a real browser if it matters to you. The
key share is X25519 alone: the post-quantum group browsers now lead with needs
a key exchange the TLS module does not have, and naming it without a share
makes nearly every server ask for it again.

And two failures are met with a second connection rather than an error. A
server that sends its leaf certificate alone gets its issuer fetched, as a
browser does. A TLS 1.2 server that signs with a scheme the browser offers but
the verifier cannot check — ECDSA with SHA-512, which old OpenSSL prefers —
gets asked again with only the schemes that can be checked. That second
ClientHello is not the browser's, but it only goes to a server that would
otherwise have been unreachable.

The browsers are data, not code: `src/fingerprint/browsers.ts`, generated from
[curl-impersonate](https://github.com/lexiforest/curl-impersonate)'s
`tests/signatures`, which are ClientHellos and HTTP/2 openings captured from
the real browsers — the same data impers is tested against. The fingerprints
each profile must match are computed from those captures, not from what we
send, so the tests compare us with the browser rather than with ourselves.

```
pnpm import:browsers     # regenerate from the pinned commit
```

The oldest captures recorded no SETTINGS frame; for those, the HTTP/2
settings come from curl-impersonate's own target table. Three impers targets
are missing — `chrome145`, `chrome146` and `firefox147` — because no capture
of them has been published.

None of the captured browsers sends PRIORITY frames — the Firefox captures
begin at 133, and its Akamai priority field is `0` like the rest — so every
Akamai string matches whole. An older Firefox's string that names some is refused
by `fromFingerprints` below rather than sent without them.

A browser that is not built in can be taken from the two strings
[tls.peet.ws/api/all](https://tls.peet.ws/api/all) shows when opened in it —
`ja3` and `akamai_fingerprint`. Neither string carries the signature
algorithms, the headers or the bodies of extensions such as ALPS, so those come
from a built-in profile of the same family:

```ts
import { fromFingerprints, profiles, Session } from 'underfetch/workers';

const edge = await fromFingerprints(
  { ja3: '771,4865-4866-…,0', akamai: '1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p' },
  profiles.chrome,
);
new Session({ impersonate: edge });
```

The JA3 then goes out exactly as given, less any post-quantum group (the same
reason as above), and `expected.ja3` says what that is. Anything the strings
ask for that cannot be sent — an extension the TLS module does not know, or
Firefox's old PRIORITY frames — is refused with a `FingerprintError` naming
it, rather than dropped. JA3 records one extension order; Chrome shuffles on
every connection, which `shuffle: true` does too.

A profile of your own is the same shape, written by hand:

```ts
const myBrowser: Impersonation = {
  alpn: ['h2', 'http/1.1'],
  http2: { settings: [...], windowUpdate: 15663105, pseudoHeaderOrder: ['m', 'a', 's', 'p'] },
  ciphers: [GREASE[0], 0x1301 /* ... */],
  signatureSchemes: [0x0403 /* ... */],
  greaseNamedGroup: true,
  extensions: () => [[0xff01, new Uint8Array([0])] /* ... */],
};

new Session({ impersonate: myBrowser });
```

Naming an `extensionOrder` makes that list authoritative: extensions the TLS
library would have added but the profile does not name are dropped, because a
browser sends what it sends and nothing more. Only what the standard requires
last — PSK and ECH — survives regardless.

A session **resumes TLS** as a returning browser does: the tickets a server
hands the first connection are offered on the next, to the same host, so its
ClientHello carries `pre_shared_key` — Chrome's JA4 becomes `t13d1517h2_…`
there. The tickets are the session's alone, never shared between sessions,
and last as long as it does; kept in a Worker's global scope, a session goes
on resuming across the requests that isolate serves. It saves the
certificate check, not a round trip: early data is never sent, as Chrome
does not send it. `tlsResumption: false` turns it off.

Two things keep a resumed hello a browser's. The key share still leads with
X25519, where rustls on its own would lead with whatever group the server
chose last time. And the empty `session_ticket` extension BoringSSL and NSS
send in every hello stays in, where rustls drops it once it holds a TLS 1.3
ticket. That rule is taken from their source: curl-impersonate publishes no
capture of a resumed hello to check the result against.

Given no profile, nothing is impersonated and no GREASE is sent. A request
that sets no `user-agent` then says `underfetch/0.1`, the way curl names
itself: impers and curl_cffi send none at all, but Reddit, Wikipedia and
ChatGPT all answer a request without one with 403.

## Proving it

Do not take the table above on trust; the library checks itself.

```
pnpm verify
```

reads a real ClientHello out of the TLS module, computes JA4 and the Akamai
string from those bytes, and compares them against what each profile claims —
no network and no third party. `pnpm test` runs the same checks.

```
ok   chrome
       ja4    t13d1516h2_8daaf6152771_d8a2da3f94cd
       akamai 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
```

That catches a profile drifting, but not the runtime rewriting something
underneath us. For that there is a second opinion, which makes real requests
through a real Worker and asks a server what it saw:

```
pnpm verify:live     # then: curl localhost:8799
```

In code, `selfTest()` from `underfetch/workers` returns the same verdicts, so a
Worker can check itself wherever it runs.

## Layout

```
src/
  index.ts        the runtime-free core, re-exported
  client/         what a caller uses: fetch, Session, redirects, retries, cookies
  http/           HTTP/1.1, and HTTP/2 with its frames and header table
  tls/            driving TLS over a socket; rustls compiled to WebAssembly
  net/            sockets and the proxy handshakes, SOCKS5 and CONNECT
  fingerprint/    the browsers, generated from captures, and the proof we match them
  workers/        the Cloudflare adapter, the only place that names a runtime
test/             the same folders as src/, run in plain node
dev/              a Worker that checks everything against real servers
scripts/          verify, and importing browsers from their captures
rust-tls/         the rustls fork and its WebAssembly build
```

## Building the WebAssembly

Only needed when `rust-tls/` changes; the output is committed.

```
make wasm
```

Needs a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-pack`,
and `clang` — `ring` compiles C for the wasm target.

## Working on it

`make` lists the rest. The ones used most:

```
make check                       # typecheck, lint, tests
make dev                         # the dev worker, its wasm cache cleared
make live AS=chrome              # fingerprints, the case matrix, resumption
make state AS=chrome             # save a session, restart, load it back
make fetch URL=https://… PROXY=socks5://host:1080
make dev-stop
```

## Licence

MIT. The vendored rustls fork under `rust-tls/vendor/` keeps its own licences
(Apache-2.0, ISC and MIT).
