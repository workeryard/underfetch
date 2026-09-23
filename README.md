# underfetch

HTTP over raw sockets for Cloudflare Workers: SOCKS5 and HTTP `CONNECT`
proxies, TLS in WebAssembly, HTTP/1.1 and HTTP/2, and a handshake that can look
like Chrome, Firefox or Safari.

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
rustls compiled to WebAssembly (517 KB, 242 KB gzipped, committed — building it
needs Rust, using it does not).

## Install

```
npm install underfetch
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

| option                           | what it does                                           |
| -------------------------------- | ------------------------------------------------------ |
| `params`                         | query parameters, merged with any already in the URL   |
| `json`                           | a JSON body, and the `content-type` that implies       |
| `form`                           | an `application/x-www-form-urlencoded` body            |
| `auth`                           | `{ bearer }` or `{ username, password }`               |
| `headers`                        | as `fetch` takes them                                  |
| `proxy`                          | overrides the session's; `null` forces this one direct |
| `timeoutMs`                      | gives up, headers and body together                    |
| `allowRedirects`, `maxRedirects` | default `true` and `20`                                |
| `retry`                          | a count, `RetryOptions`, or `false`                    |
| `impersonate`                    | whose ClientHello to send                              |

What comes back is a plain `Response`, deliberately. It already carries
`status`, `headers`, `text()` and `json()`, and unlike a bespoke response
object it leaves the body **streaming** — server-sent events arrive event by
event, and nothing waits for the whole answer. After redirects, `response.url`
is where the chain ended.

A redirect that changes host drops `authorization` and `cookie`. A 307 or 308
repeats the request body, so a body is buffered before the first hop; if that
matters, turn redirects off.

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
import { proxyFetch } from 'underfetch';

await proxyFetch(request, { dial, tls, proxy });
```

`dial` opens a TCP connection and returns `{ readable, writable, close }`.
`tls` returns a session with `receive`, `outgoing`, `send`, `plaintext`,
`handshaking` and `close` — a sans-I/O state machine, so swapping in a
different TLS stack means implementing six methods.

## What it does and does not do

|                                                  |                             |
| ------------------------------------------------ | --------------------------- |
| SOCKS5, with username/password auth              | yes                         |
| HTTP `CONNECT`, with basic auth                  | yes                         |
| TLS 1.2 and 1.3, certificates verified           | yes                         |
| Short certificate chains completed from AIA      | yes, as browsers do         |
| Streaming request and response bodies            | yes                         |
| gzip and deflate, undone transparently           | yes                         |
| Timeouts and `AbortSignal`                       | yes                         |
| Redirects, with credentials dropped across hosts | yes                         |
| HTTP/2, with HPACK and flow control              | yes                         |
| Browser impersonation, TLS and HTTP/2            | 16 browsers, see below      |
| Cookies, with domain and path scoping            | yes                         |
| Retries, idempotent methods only by default      | yes                         |
| HTTP/3                                           | never — a Worker has no UDP |

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

A profile also carries the browser's **request headers in the browser's
order** — `user-agent`, `accept`, `sec-ch-ua`, `sec-fetch-*` and the rest —
because a handshake that matches Chrome while the headers say "not a browser"
fools nobody. Headers a session or a request sets win over the profile's.

Where it cannot be the browser, it says so. `accept-encoding` is ours
(`gzip, deflate`) rather than the browser's `gzip, deflate, br, zstd`:
`DecompressionStream` has no brotli and no zstd, and advertising what cannot be
decoded is how a handshake breaks. The `sec-ch-ua` brand list rotates between
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

Firefox also sends PRIORITY frames, which are not reproduced — its Akamai
string is right in every other field.

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

Given no profile, nothing is impersonated and no GREASE is sent.

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
pnpm build:wasm
```

Needs a Rust toolchain with the `wasm32-unknown-unknown` target, `wasm-pack`,
and `clang` — `ring` compiles C for the wasm target.

## Licence

MIT. The vendored rustls fork under `rust-tls/vendor/` keeps its own licences
(Apache-2.0, ISC and MIT).
