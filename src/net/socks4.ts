/**
 * SOCKS4, as 4a: the target goes to the proxy as a name, so DNS is resolved
 * there rather than leaking from the Worker — the same promise SOCKS5 keeps.
 * An IPv4 address goes as itself; IPv6 SOCKS4 cannot carry at all.
 */

import { ByteReader, ByteWriter } from './bytes';
import type { ByteSocket, Socks4Proxy } from './socket';

const VERSION = 0x04;
const CMD_CONNECT = 0x01;
const GRANTED = 0x5a;

/** What the reply code means, for the ones SOCKS4 defines. */
const REPLIES: Record<number, string> = {
  0x5b: 'rejected or failed',
  0x5c: 'rejected: the proxy could not reach identd on the client',
  0x5d: 'rejected: identd did not confirm the user ID',
};

export class Socks4Error extends Error {
  override name = 'Socks4Error';
}

function ipv4(hostname: string): number[] | null {
  const parts = hostname.split('.');
  if (parts.length !== 4) return null;
  const bytes = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : NaN));
  return bytes.every((b) => b >= 0 && b <= 255) ? bytes : null;
}

/** The CONNECT request: 4a's placeholder address when naming the target. */
export function socks4Request(hostname: string, port: number, userId = ''): Uint8Array {
  if (hostname.includes(':')) throw new Socks4Error('SOCKS4 cannot reach an IPv6 address');
  const encoder = new TextEncoder();
  const address = ipv4(hostname);
  const bytes = [
    VERSION,
    CMD_CONNECT,
    port >> 8,
    port & 0xff,
    // 0.0.0.x with x nonzero tells a 4a proxy the name follows the user ID.
    ...(address ?? [0, 0, 0, 1]),
    ...encoder.encode(userId),
    0,
  ];
  if (address === null) bytes.push(...encoder.encode(hostname), 0);
  return new Uint8Array(bytes);
}

/**
 * Asks `proxy` for a tunnel to `hostname:port`. The returned socket is the one
 * dialled; its streams now carry the target's bytes.
 */
export async function socks4Connect(
  socket: ByteSocket,
  proxy: Socks4Proxy,
  hostname: string,
  port: number,
): Promise<ByteSocket> {
  const writer = new ByteWriter(socket.writable);
  await writer.write(socks4Request(hostname, port, proxy.username));
  writer.release();

  const reader = new ByteReader(socket.readable);
  // VN (0), CD, then a port and address that CONNECT leaves meaningless.
  const reply = await reader.exactly(8);
  if (reply[0] !== 0) throw new Socks4Error(`the proxy did not answer as SOCKS4 (${reply[0]})`);
  if (reply[1] !== GRANTED) {
    const why = REPLIES[reply[1]!] ?? `code ${reply[1]}`;
    throw new Socks4Error(`the proxy would not reach ${hostname}:${port}: ${why}`);
  }
  return { readable: reader.rest(), writable: socket.writable, close: () => socket.close() };
}
