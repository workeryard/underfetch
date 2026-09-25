// Records the header order and HTTP/2 stream weight of every request a real
// browser makes — how the tables in src/fingerprint/order.ts were measured.
//
//   openssl ...            make a CA and a localhost leaf signed by it (key.pem,
//                          cert.pem, ca.pem) in the working directory
//   PORT=8443 OUT=edge.json pnpm tsx scripts/capture-headers.ts
//   msedge.exe --headless=new --ignore-certificate-errors \
//     --user-data-dir=<a scratch dir> --virtual-time-budget=10000 \
//     --dump-dom https://localhost:8443/
//
// Firefox will not skip certificate checks, so give it a throwaway profile
// that trusts only the CA, with NSS certutil:
//   certutil -N -d sql:<profile> --empty-password
//   certutil -A -d sql:<profile> -n capture-ca -t "C,," -i ca.pem
//   firefox.exe --headless --no-remote --profile <profile> https://localhost:8443/
//
// The page it serves makes every kind of request: a navigation, style, script
// and image, fetch() GET and POST, XHR, a CORS preflight, no-store, the page's
// own headers alone and together, and a form POST navigation. Each request is
// appended to OUT as it arrives.
import http2, { type ServerHttp2Stream } from 'node:http2';
import { readFileSync, writeFileSync } from 'node:fs';

interface Seen {
  weight: number | undefined;
  path: string;
  method: string | undefined;
  /** The regular headers and pseudo-headers, in the order they arrived. */
  names: string[];
  [header: string]: unknown;
}

const log: Seen[] = [];
const page = `<!doctype html><html><head><link rel="stylesheet" href="/s.css"><script src="/s.js"></script></head>
<body><img src="/i.png"><form id="f" method="POST" action="/form-nav"><input name="a" value="b"></form>
<script>
(async () => {
  await fetch('/api/get').catch(()=>{});
  await fetch('/api/post-json', {method:'POST', headers:{'content-type':'application/json'}, body:'{"a":1}'}).catch(()=>{});
  await fetch('/api/post-form', {method:'POST', body:new URLSearchParams({a:'b'})}).catch(()=>{});
  await new Promise(r => { const x = new XMLHttpRequest(); x.open('GET','/api/xhr'); x.onloadend=r; x.send(); });
  await fetch('https://127.0.0.1:' + location.port + '/api/cors-get').catch(()=>{});
  await fetch('https://127.0.0.1:' + location.port + '/api/cors-post', {method:'POST', headers:{'content-type':'application/json'}, body:'{}'}).catch(()=>{});
  await fetch('/api/no-store', {cache:'no-store'}).catch(()=>{});
  await fetch('/api/custom-get', {headers:{'authorization':'Bearer x','x-api-key':'k'}}).catch(()=>{});
  await fetch('/api/custom-post', {method:'POST', headers:{'content-type':'application/json','authorization':'Bearer x','x-api-key':'k'}, body:'{}'}).catch(()=>{});
  await fetch('/h/one-authorization', {headers:{'authorization':'v'}}).catch(()=>{});
  await fetch('/h/one-x-api-key', {headers:{'x-api-key':'v'}}).catch(()=>{});
  await fetch('/h/one-x-requested-with', {headers:{'x-requested-with':'v'}}).catch(()=>{});
  await fetch('/h/one-x-csrf-token', {headers:{'x-csrf-token':'v'}}).catch(()=>{});
  await fetch('/h/one-x-client-id', {headers:{'x-client-id':'v'}}).catch(()=>{});
  await fetch('/h/one-content-type', {headers:{'content-type':'v'}}).catch(()=>{});
  await fetch('/h/all', {headers:{'authorization':'v','x-api-key':'v','x-requested-with':'v','x-csrf-token':'v','x-client-id':'v','content-type':'v'}}).catch(()=>{});
  await fetch('/h/all-reversed', {headers:{'content-type':'v','x-client-id':'v','x-csrf-token':'v','x-requested-with':'v','x-api-key':'v','authorization':'v'}}).catch(()=>{});
  await fetch('/h/pair', {headers:{'x-requested-with':'v','authorization':'v'}}).catch(()=>{});
  document.getElementById('f').submit();
})();
</script></body></html>`;
const server = http2.createSecureServer({
  key: readFileSync('key.pem'),
  cert: readFileSync('cert.pem'),
  allowHTTP1: true,
});
server.on('stream', (stream: ServerHttp2Stream, headers, _flags, raw: string[]) => {
  const names: string[] = [];
  for (let i = 0; i < raw.length; i += 2) names.push(raw[i]!);
  const path = headers[':path'] ?? '/';
  log.push({
    weight: stream.state?.weight,
    path,
    method: headers[':method'],
    names,
    ua: headers['user-agent'],
    priority: headers['priority'],
    accept: headers['accept'],
    site: headers['sec-fetch-site'],
    mode: headers['sec-fetch-mode'],
    dest: headers['sec-fetch-dest'],
    origin: headers['origin'],
    referer: headers['referer'],
    cookie: headers['cookie'],
  });
  writeFileSync(process.env.OUT || 'capture.json', JSON.stringify(log, null, 1));
  const cors = {
    'access-control-allow-origin': 'https://localhost:' + process.env.PORT,
    'access-control-allow-headers': '*',
    'access-control-allow-methods': 'POST, GET',
  };
  if (path === '/')
    stream.respond({
      ':status': 200,
      'content-type': 'text/html',
      'set-cookie': 'sid=abc; Path=/; Secure',
      'cache-control': 'no-store',
    });
  else
    stream.respond({
      ':status': 200,
      'content-type': path.endsWith('.css')
        ? 'text/css'
        : path.endsWith('.js')
          ? 'text/javascript'
          : 'text/plain',
      ...cors,
    });
  stream.end(path === '/' ? page : path === '/s.js' ? '' : 'ok');
});
server.on('tlsClientError', (e) => console.log('tls error', e.message));
server.listen(Number(process.env.PORT), '0.0.0.0', () =>
  console.log('listening', process.env.PORT),
);
