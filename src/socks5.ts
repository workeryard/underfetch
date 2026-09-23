/**
 * SOCKS5 (RFC 1928) with username/password auth (RFC 1929).
 *
 * Only the client half of CONNECT is here: greet, authenticate, ask for the
 * target, and hand back a tunnel carrying nothing but the target's own bytes.
 */

import { ByteReader, ByteWriter } from './bytes';
import type { ByteSocket, Socks5Proxy } from './socket';

const VERSION = 0x05;
const CMD_CONNECT = 0x01;
const RESERVED = 0x00;

const AUTH_NONE = 0x00;
const AUTH_PASSWORD = 0x02;
const AUTH_REJECTED = 0xff;
const AUTH_VERSION = 0x01;

const ADDR_IPV4 = 0x01;
const ADDR_DOMAIN = 0x03;
const ADDR_IPV6 = 0x04;

/** RFC 1928 §6: the reply field, in the order the RFC lists them. */
const REPLY_MESSAGES = [
  'succeeded',
  'general SOCKS server failure',
  'connection not allowed by ruleset',
  'network unreachable',
  'host unreachable',
  'connection refused',
  'TTL expired',
  'command not supported',
  'address type not supported',
];

export class Socks5Error extends Error {
  override name = 'Socks5Error';
}

function ascii(text: string, field: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > 255) throw new Socks5Error(`${field} is longer than 255 bytes`);
  return bytes;
}

/**
 * The target address, always as a domain name when we have one: letting the
 * proxy resolve it is the point — a name resolved here would leak our DNS and
 * pin the connection to an IP our own resolver picked.
 */
function targetAddress(hostname: string, port: number): Uint8Array {
  const name = ascii(hostname, 'hostname');
  const request = new Uint8Array(4 + 1 + name.length + 2);
  request[0] = VERSION;
  request[1] = CMD_CONNECT;
  request[2] = RESERVED;
  request[3] = ADDR_DOMAIN;
  request[4] = name.length;
  request.set(name, 5);
  new DataView(request.buffer).setUint16(5 + name.length, port);
  return request;
}

/** Consumes the bound address in a reply, whose length depends on its type. */
async function skipBoundAddress(reader: ByteReader): Promise<void> {
  const type = await reader.byte();
  if (type === ADDR_IPV4) await reader.exactly(4);
  else if (type === ADDR_IPV6) await reader.exactly(16);
  else if (type === ADDR_DOMAIN) await reader.exactly(await reader.byte());
  else throw new Socks5Error(`the proxy replied with unknown address type ${type}`);
  await reader.exactly(2); // port
}

async function authenticate(
  reader: ByteReader,
  writer: ByteWriter,
  proxy: Socks5Proxy,
): Promise<void> {
  const password = proxy.username !== undefined && proxy.password !== undefined;
  const methods = password ? [AUTH_PASSWORD, AUTH_NONE] : [AUTH_NONE];
  await writer.write(new Uint8Array([VERSION, methods.length, ...methods]));

  const version = await reader.byte();
  if (version !== VERSION) {
    throw new Socks5Error(`the proxy answered with SOCKS version ${version}, not 5`);
  }

  const chosen = await reader.byte();
  if (chosen === AUTH_NONE) return;
  if (chosen === AUTH_REJECTED) {
    throw new Socks5Error(
      password
        ? 'the proxy rejected both username/password and open access'
        : 'the proxy requires authentication but none was configured',
    );
  }
  if (chosen !== AUTH_PASSWORD) {
    throw new Socks5Error(`the proxy asked for auth method ${chosen}, which we do not speak`);
  }
  if (!password) throw new Socks5Error('the proxy asked for a username and password');

  const user = ascii(proxy.username ?? '', 'username');
  const secret = ascii(proxy.password ?? '', 'password');
  const request = new Uint8Array(3 + user.length + secret.length);
  request[0] = AUTH_VERSION;
  request[1] = user.length;
  request.set(user, 2);
  request[2 + user.length] = secret.length;
  request.set(secret, 3 + user.length);
  await writer.write(request);

  await reader.byte(); // the server echoes the auth version
  if ((await reader.byte()) !== 0)
    throw new Socks5Error('the proxy rejected the username/password');
}

/**
 * Opens a tunnel to `hostname:port` through `proxy`. The returned socket is the
 * one that was dialled, so closing it closes the tunnel; its streams now carry
 * the target's bytes and nothing else.
 */
export async function socks5Connect(
  socket: ByteSocket,
  proxy: Socks5Proxy,
  hostname: string,
  port: number,
): Promise<ByteSocket> {
  const reader = new ByteReader(socket.readable);
  const writer = new ByteWriter(socket.writable);

  await authenticate(reader, writer, proxy);
  await writer.write(targetAddress(hostname, port));

  const version = await reader.byte();
  if (version !== VERSION) {
    throw new Socks5Error(`the proxy answered with SOCKS version ${version}, not 5`);
  }
  const reply = await reader.byte();
  if (reply !== 0) {
    const reason = REPLY_MESSAGES[reply] ?? `unknown failure ${reply}`;
    throw new Socks5Error(`the proxy could not reach ${hostname}:${port}: ${reason}`);
  }
  await reader.byte(); // reserved
  await skipBoundAddress(reader);

  writer.release();
  // Anything the target already sent is buffered in the reader, so the tunnel
  // has to read through it rather than from the raw stream.
  return {
    readable: reader.rest(),
    writable: socket.writable,
    close: () => socket.close(),
  };
}
