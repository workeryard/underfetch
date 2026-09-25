/**
 * HTTP `CONNECT` tunnelling (RFC 9110 §9.3.6).
 *
 * The other half of "a proxy": where SOCKS5 speaks its own binary handshake, an
 * HTTP proxy is asked in plain text and answers with a status line. Everything
 * after a 200 is the target's own bytes.
 */

import { ByteReader, ByteWriter } from './bytes';
import type { ByteSocket, HttpProxy, HttpsProxy } from './socket';

export class HttpConnectError extends Error {
  override name = 'HttpConnectError';
}

function credentials(proxy: HttpProxy | HttpsProxy): string | null {
  if (proxy.username === undefined || proxy.password === undefined) return null;
  return `Basic ${btoa(`${proxy.username}:${proxy.password}`)}`;
}

/**
 * Asks `proxy` to open a tunnel to `hostname:port`. The returned socket is the
 * one that was dialled; its streams now carry the target's bytes.
 */
export async function httpConnect(
  socket: ByteSocket,
  proxy: HttpProxy | HttpsProxy,
  hostname: string,
  port: number,
): Promise<ByteSocket> {
  const authority = `${hostname}:${port}`;
  const lines = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
  const auth = credentials(proxy);
  if (auth !== null) lines.push(`Proxy-Authorization: ${auth}`);

  const writer = new ByteWriter(socket.writable);
  await writer.write(new TextEncoder().encode(`${lines.join('\r\n')}\r\n\r\n`));

  const reader = new ByteReader(socket.readable);
  const status = await reader.line();
  const match = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(status);
  if (!match) {
    throw new HttpConnectError(`the proxy did not answer with HTTP: ${status.slice(0, 80)}`);
  }
  const code = Number(match[1]);
  if (code !== 200) {
    // 407 is the one worth naming: it means the credentials were the problem.
    const why = code === 407 ? 'the proxy requires authentication' : (match[2] ?? 'refused');
    throw new HttpConnectError(`the proxy could not reach ${authority}: ${code} ${why}`);
  }

  // A tunnel reply carries headers of its own, which end at the blank line.
  while ((await reader.line()) !== '') continue;

  writer.release();
  return {
    readable: reader.rest(),
    writable: socket.writable,
    close: () => socket.close(),
  };
}
