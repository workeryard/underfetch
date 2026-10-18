// Records a real browser's ClientHello — its JA3 and JA4, worked out by the
// same code that checks our profiles — and every HTTP/2 frame it sends: each
// HEADERS frame's stream, its priority fields (exclusive bit, the stream it
// depends on, weight) and its :path and priority header, and every
// SETTINGS, WINDOW_UPDATE, PRIORITY and PRIORITY_UPDATE frame. What
// `capture-headers.ts` cannot see: node's http2 reports a stream's weight
// and nothing of what it depends on.
//
// TLS is ended here, the frames are read as they pass, and the bytes go on
// to node's own HTTP/2 server over plain TCP, which serves the page.
//
//   (key.pem and cert.pem as for capture-headers.ts, in the working directory)
//   PORT=8443 OUT=chrome-frames.json pnpm tsx scripts/capture-frames.ts
//   chrome.exe --headless=new --ignore-certificate-errors \
//     --user-data-dir=<a scratch dir> --virtual-time-budget=10000 \
//     --dump-dom https://localhost:8443/
//
// The page loads in waves: four images at once, then four fetch() calls at
// once, then two fetch() calls one after the other, so streams that overlap
// and streams that do not are both seen.
import http2 from 'node:http2';
import { connect, type AddressInfo } from 'node:net';
import { createServer as createRawServer, type Socket } from 'node:net';
import { createServer } from 'node:tls';
import { readFileSync, writeFileSync } from 'node:fs';
import { Hpack } from '../src/http/h2/hpack';
import { ja3, ja4, parseClientHello } from '../src/fingerprint/verify';

const page = `<!doctype html><html><head><title>frames</title></head><body>
<img src="/img/1.png"><img src="/img/2.png"><img src="/img/3.png"><img src="/img/4.png">
<script>
(async () => {
  await new Promise((r) => setTimeout(r, 300));
  await Promise.all(['a', 'b', 'c', 'd'].map((n) => fetch('/together/' + n).then((r) => r.text())));
  await fetch('/after/1').then((r) => r.text());
  await fetch('/after/2').then((r) => r.text());
  document.title = 'done';
})();
</script></body></html>`;

// Slow answers keep concurrent streams open long enough to overlap.
const backend = http2.createServer((request, response) => {
  const path = request.url;
  const delay = path.startsWith('/img/') || path.startsWith('/together/') ? 200 : 0;
  setTimeout(() => {
    if (path === '/') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end(page);
    } else {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end(path);
    }
  }, delay);
});
backend.listen(0, '127.0.0.1');

interface Logged {
  connection: number;
  at: number;
  type: string;
  stream: number;
  [field: string]: unknown;
}
const log: Logged[] = [];
const TYPES: Record<number, string> = {
  0x0: 'DATA',
  0x1: 'HEADERS',
  0x2: 'PRIORITY',
  0x3: 'RST_STREAM',
  0x4: 'SETTINGS',
  0x6: 'PING',
  0x7: 'GOAWAY',
  0x8: 'WINDOW_UPDATE',
  0x9: 'CONTINUATION',
  0x10: 'PRIORITY_UPDATE',
};
const PREFACE_LENGTH = 24;
let connections = 0;
const started = Date.now();

const front = createServer(
  { key: readFileSync('key.pem'), cert: readFileSync('cert.pem'), ALPNProtocols: ['h2'] },
  (client) => {
    const connection = ++connections;
    const hpack = new Hpack(65536);
    let buffer = Buffer.alloc(0);
    let preface = false;
    const upstream = connect((backend.address() as AddressInfo).port, '127.0.0.1');
    client.on('data', (chunk: Buffer) => {
      upstream.write(chunk);
      buffer = Buffer.concat([buffer, chunk]);
      if (!preface) {
        if (buffer.length < PREFACE_LENGTH) return;
        buffer = buffer.subarray(PREFACE_LENGTH);
        preface = true;
      }
      while (buffer.length >= 9) {
        const length = buffer.readUIntBE(0, 3);
        if (buffer.length < 9 + length) return;
        const type = buffer[3]!;
        const flags = buffer[4]!;
        const stream = buffer.readUInt32BE(5) & 0x7fffffff;
        const payload = buffer.subarray(9, 9 + length);
        buffer = buffer.subarray(9 + length);
        const entry: Logged = {
          connection,
          at: Date.now() - started,
          type: TYPES[type] ?? `0x${type.toString(16)}`,
          stream,
        };
        if (type === 0x1) {
          let block = payload;
          if (flags & 0x8) block = block.subarray(1, block.length - block[0]!);
          if (flags & 0x20) {
            const word = block.readUInt32BE(0);
            entry.exclusive = (word & 0x80000000) !== 0;
            entry.dependsOn = word & 0x7fffffff;
            entry.weight = block[4]! + 1;
            block = block.subarray(5);
          } else {
            entry.priorityFlag = false;
          }
          entry.endStream = (flags & 0x1) !== 0;
          const headers = hpack.decode(new Uint8Array(block));
          entry.path = headers.find(([name]) => name === ':path')?.[1];
          entry.priority = headers.find(([name]) => name === 'priority')?.[1];
          entry.headers = headers;
        } else if (type === 0x2) {
          const word = payload.readUInt32BE(0);
          entry.exclusive = (word & 0x80000000) !== 0;
          entry.dependsOn = word & 0x7fffffff;
          entry.weight = payload[4]! + 1;
        } else if (type === 0x4 && (flags & 0x1) === 0) {
          const settings: [number, number][] = [];
          for (let at = 0; at + 6 <= payload.length; at += 6) {
            settings.push([payload.readUInt16BE(at), payload.readUInt32BE(at + 2)]);
          }
          entry.settings = settings;
        } else if (type === 0x8) {
          entry.increment = payload.readUInt32BE(0) & 0x7fffffff;
        } else if (type === 0x10) {
          entry.prioritized = payload.readUInt32BE(0) & 0x7fffffff;
          entry.field = payload.subarray(4).toString('latin1');
        } else if (type === 0x0 || type === 0x6 || (type === 0x4 && flags & 0x1)) {
          continue; // bodies, pings and acknowledgements say nothing here
        }
        log.push(entry);
        writeFileSync(process.env.OUT ?? 'frames.json', JSON.stringify(log, null, 1));
      }
    });
    upstream.pipe(client);
    const close = () => {
      client.destroy();
      upstream.destroy();
    };
    client.on('error', close);
    upstream.on('error', close);
    client.on('close', close);
  },
);
// The ClientHello is read off the raw socket on its way through: the bytes
// are relayed to the TLS server on a port of its own, since a TLS socket reads
// its handle directly and would never see bytes put back on this one.
front.listen(0, '127.0.0.1');
const raw = createRawServer((socket: Socket) => {
  const inner = connect((front.address() as AddressInfo).port, '127.0.0.1');
  let held = Buffer.alloc(0);
  let seen = false;
  socket.on('data', (chunk: Buffer) => {
    inner.write(chunk);
    if (seen) return;
    held = Buffer.concat([held, chunk]);
    if (held.length < 5 || held.length < 5 + held.readUInt16BE(3)) return;
    seen = true;
    const record = new Uint8Array(held.subarray(0, 5 + held.readUInt16BE(3)));
    void (async () => {
      try {
        const hello = parseClientHello(record);
        log.push({
          connection: connections + 1,
          at: Date.now() - started,
          type: 'CLIENT_HELLO',
          stream: 0,
          ja3: ja3(hello),
          ja4: await ja4(hello),
          hello,
          bytes: Buffer.from(record).toString('hex'),
        });
      } catch (error) {
        log.push({ connection: 0, at: 0, type: 'CLIENT_HELLO', stream: 0, error: String(error) });
      }
      writeFileSync(process.env.OUT ?? 'frames.json', JSON.stringify(log, null, 1));
    })();
  });
  inner.pipe(socket);
  const close = () => {
    socket.destroy();
    inner.destroy();
  };
  socket.on('error', close);
  inner.on('error', close);
  socket.on('close', close);
  inner.on('close', close);
});

raw.listen(Number(process.env.PORT ?? 8443), () =>
  console.log(
    `https://localhost:${process.env.PORT ?? 8443}/ writing ${process.env.OUT ?? 'frames.json'}`,
  ),
);
