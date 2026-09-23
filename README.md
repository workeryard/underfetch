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
  "rules": [{ "type": "CompiledWasm", "globs": ["**/*.wasm"], "fallback": true }]
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

`Session.fetch` takes what `fetch` takes, plus `proxy` and `timeoutMs`, and
returns a normal `Response` whose body is still streaming. Server-sent events
arrive event by event; nothing waits for the whole answer.

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

| | |
| --- | --- |
| SOCKS5, with username/password auth | yes |
| HTTP `CONNECT`, with basic auth | yes |
| TLS 1.2 and 1.3, certificates verified | yes |
| Streaming request and response bodies | yes |
| gzip and deflate, undone transparently | yes |
| Timeouts and `AbortSignal` | yes |
| GREASE in the ClientHello | yes |
| HTTP/2 | not yet |
| Browser fingerprint impersonation | in progress |
| HTTP/3 | never — a Worker has no UDP |

The target hostname is sent to the proxy as a name, not an address, so DNS is
resolved at the proxy rather than leaking from the Worker.

## The fingerprint

The bundled rustls is a fork, because a stock rustls ClientHello is
recognisable at a glance: it sends no GREASE, and nothing else on the web omits
it. The fork adds GREASE to the cipher list, the supported groups and the
extension list.

It is not yet a browser. Chrome offers 15 cipher suites to our 10, 16
extensions to our 11, and `h2` where we can only honestly offer `http/1.1` —
advertising `h2` without speaking it would break the handshake the moment a
server took us up on it. So HTTP/2 comes before the fingerprint can match.

Measure for yourself rather than trusting this paragraph:

```ts
const response = await new Session().fetch('https://tls.peet.ws/api/all');
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
