/** Opening a tunnel through whichever kind of proxy was configured. */

import { httpConnect } from './http-connect';
import { socks4Connect } from './socks4';
import { socks5Connect } from './socks5';
import type { ByteSocket, Proxy } from './socket';

/**
 * Asks the proxy for a tunnel to `hostname:port`. For an HTTPS proxy,
 * `socket` must already be the TLS connection to it.
 */
export function tunnelThrough(
  socket: ByteSocket,
  proxy: Proxy,
  hostname: string,
  port: number,
): Promise<ByteSocket> {
  switch (proxy.kind) {
    case 'http':
    case 'https':
      return httpConnect(socket, proxy, hostname, port);
    case 'socks4':
      return socks4Connect(socket, proxy, hostname, port);
    case 'socks5':
      return socks5Connect(socket, proxy, hostname, port);
  }
}
