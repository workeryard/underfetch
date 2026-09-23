/** Opening a tunnel through whichever kind of proxy was configured. */

import { httpConnect } from './http-connect';
import { socks5Connect } from './socks5';
import type { ByteSocket, Proxy } from './socket';

export function tunnelThrough(
  socket: ByteSocket,
  proxy: Proxy,
  hostname: string,
  port: number,
): Promise<ByteSocket> {
  return proxy.kind === 'http'
    ? httpConnect(socket, proxy, hostname, port)
    : socks5Connect(socket, proxy, hostname, port);
}
