# underfetch

HTTP over raw sockets for Cloudflare Workers: SOCKS5 and HTTP `CONNECT`
proxies, TLS in WebAssembly, and a ClientHello you control.

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
| `impersonate`                    | whose ClientHello to send                              |

What comes back is a plain `Response`, deliberately. It already carries
`status`, `headers`, `text()` and `json()`, and unlike a bespoke response
object it leaves the body **streaming** — server-sent events arrive event by
event, and nothing waits for the whole answer. After redirects, `response.url`
is where the chain ended.

A redirect that changes host drops `authorization` and `cookie`. A 307 or 308
repeats the request body, so a body is buffered before the first hop; if that
matters, turn redirects off.

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

|                                        |                             |
| -------------------------------------- | --------------------------- |
| SOCKS5, with username/password auth    | yes                         |
| HTTP `CONNECT`, with basic auth        | yes                         |
| TLS 1.2 and 1.3, certificates verified | yes                         |
| Streaming request and response bodies  | yes                         |
| gzip and deflate, undone transparently | yes                         |
| Timeouts and `AbortSignal`             | yes                         |
| GREASE in the ClientHello              | yes                         |
| HTTP/2                                 | not yet                     |
| Browser fingerprint impersonation      | in progress                 |
| HTTP/3                                 | never — a Worker has no UDP |

The target hostname is sent to the proxy as a name, not an address, so DNS is
resolved at the proxy rather than leaking from the Worker.

## The fingerprint

A stock rustls ClientHello is recognisable at a glance: it sends no GREASE, and
nothing else on the web omits it. Ask for a browser instead:

```ts
const session = new Session({ impersonate: 'chrome' });
```

Chrome 133's TLS fingerprint then matches exactly, bar its ALPN:

|     | ours                                   | Chrome 133                             |
| --- | -------------------------------------- | -------------------------------------- |
| JA4 | `t13d1516h1_8daaf6152771_d8a2da3f94cd` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` |

The `h1` is the one gap, and it is honest: Chrome offers `h2`, and advertising
it before HTTP/2 exists here would fail the first handshake a server accepted
it on. So HTTP/2 comes before the fingerprint can be complete.

A profile is data, not code — see `src/impersonate.ts`. Adding a browser means
writing down what it sends, taken from
[utls](https://github.com/refraction-networking/utls)'s `u_parrots.go`:

```ts
const myBrowser: Impersonation = {
  alpn: ['http/1.1'],
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
