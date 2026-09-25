/**
 * Opening a WebSocket: the HTTP/1.1 Upgrade, over a connection of its own.
 *
 * A browser does the same. HTTP/2 has no Upgrade, so Chrome opens WebSockets
 * on a fresh connection whose ALPN offers `http/1.1` alone — its JA4 there
 * ends `h1`, and so does ours.
 */

import { ByteReader, ByteWriter } from '../net/bytes';
import { readResponseHead } from '../http/http1';
import { USER_AGENT } from '../http/user-agent';
import { acceptedDeflate, DEFLATE_OFFER, type InflaterFactory } from '../http/permessage-deflate';
import { WebSocketConnection, WebSocketError, type Deflate } from '../http/websocket';
import { deadline, until } from './abort';
import { openCarrier, remedied, type FetchOverOptions } from './fetch';

export interface WebSocketOptions {
  /** Offered as `Sec-WebSocket-Protocol`; the server may pick one. */
  protocols?: readonly string[] | undefined;
  /** Sent with the Upgrade. A browser always sends `origin`; nothing here does unless told. */
  headers?: HeadersInit | undefined;
  /** Gives up on the handshake after this many milliseconds. */
  timeoutMs?: number | undefined;
  /** Gives up on connecting — dial, proxy, TLS — after this many. */
  connectTimeoutMs?: number | undefined;
  /** Closes the connection when aborted, handshake or not. */
  signal?: AbortSignal | undefined;
  /** A message larger than this closes the connection with 1009. Default: 16 MiB. */
  maxMessageBytes?: number | undefined;
}

export interface WebSocketConnectOptions
  extends
    WebSocketOptions,
    Pick<FetchOverOptions, 'dial' | 'tls' | 'proxy' | 'completeChains' | 'connectTimeoutMs'> {
  /**
   * Reads permessage-deflate, which is offered only when this is given: a
   * compressed message nothing can inflate would end the connection.
   */
  inflater?: InflaterFactory | undefined;
}

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

/**
 * The Upgrade's headers in the order Chrome writes them; whatever else the
 * caller gave follows. Written from Chrome's known handshake, not from a
 * capture, which curl-impersonate does not publish for WebSockets.
 */
function handshakeHead(url: URL, key: string, options: WebSocketConnectOptions): string {
  const given = new Headers(options.headers);
  const lines = [
    `GET ${url.pathname}${url.search} HTTP/1.1`,
    `Host: ${url.host}`,
    'Connection: Upgrade',
    'Pragma: no-cache',
    'Cache-Control: no-cache',
    `User-Agent: ${given.get('user-agent') ?? USER_AGENT}`,
    'Upgrade: websocket',
  ];
  const optional = (name: string, label: string) => {
    const value = given.get(name);
    if (value !== null) lines.push(`${label}: ${value}`);
  };
  optional('origin', 'Origin');
  lines.push('Sec-WebSocket-Version: 13');
  optional('accept-encoding', 'Accept-Encoding');
  optional('accept-language', 'Accept-Language');
  optional('cookie', 'Cookie');
  lines.push(`Sec-WebSocket-Key: ${key}`);
  if (options.inflater) lines.push(`Sec-WebSocket-Extensions: ${DEFLATE_OFFER}`);
  if (options.protocols?.length)
    lines.push(`Sec-WebSocket-Protocol: ${options.protocols.join(', ')}`);

  const written = new Set([
    'host',
    'connection',
    'pragma',
    'cache-control',
    'user-agent',
    'upgrade',
    'origin',
    'accept-encoding',
    'accept-language',
    'cookie',
  ]);
  for (const [name, value] of given) {
    if (written.has(name) || name.startsWith('sec-websocket-')) continue;
    lines.push(`${name}: ${value}`);
  }
  return `${lines.join('\r\n')}\r\n\r\n`;
}

async function expectedAccept(key: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(key + GUID));
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

export class WebSocketRefused extends WebSocketError {
  override name = 'WebSocketRefused';
  constructor(
    readonly status: number,
    readonly headers: Headers,
  ) {
    super(`the server answered the Upgrade with ${status}, not 101`);
  }
}

/**
 * Opens a WebSocket to `input` (`wss:`/`ws:`, or `https:`/`http:` for the same
 * thing). What comes back is open; a server that will not upgrade throws
 * `WebSocketRefused`, carrying its status and headers.
 */
export async function connectWebSocket(
  input: string | URL,
  options: WebSocketConnectOptions,
): Promise<{ socket: WebSocketConnection; headers: Headers }> {
  const url = new URL(input);
  const scheme = { 'wss:': 'wss:', 'https:': 'wss:', 'ws:': 'ws:', 'http:': 'ws:' }[url.protocol];
  if (scheme === undefined) throw new TypeError(`cannot open a WebSocket to ${url.protocol}`);
  url.protocol = scheme;
  url.hash = '';

  const limit = deadline(options.signal, options.timeoutMs);
  const key = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));

  const carrier = await remedied(options, limit.signal, (tls) =>
    openCarrier(url, options, tls, limit.signal, 'http/1.1'),
  );
  const shut = () => void carrier.socket.close().catch(() => undefined);
  try {
    const writer = new ByteWriter(carrier.writable);
    await until(
      limit.signal,
      writer.write(new TextEncoder().encode(handshakeHead(url, key, options))),
    );
    writer.release();

    const reader = new ByteReader(carrier.readable);
    const { status, headers } = await until(limit.signal, readResponseHead(reader));
    if (status !== 101) throw new WebSocketRefused(status, headers);
    if (headers.get('upgrade')?.toLowerCase() !== 'websocket') {
      throw new WebSocketError('the server said 101 but not to websocket');
    }
    if (headers.get('sec-websocket-accept') !== (await expectedAccept(key))) {
      throw new WebSocketError('the server answered the wrong Sec-WebSocket-Accept');
    }
    const chosen = headers.get('sec-websocket-protocol') ?? '';
    if (chosen !== '' && !options.protocols?.includes(chosen)) {
      throw new WebSocketError(`the server chose a subprotocol never offered: ${chosen}`);
    }
    // What was not offered may not be accepted: a compressed frame
    // would be unreadable.
    const extensions = headers.get('sec-websocket-extensions');
    let deflate: Deflate | undefined;
    if (extensions !== null) {
      if (!options.inflater) {
        throw new WebSocketError('the server turned on an extension never offered');
      }
      deflate = { create: options.inflater, terms: acceptedDeflate(extensions) };
    }

    // The handshake's deadline is spent; the caller's own signal still holds.
    carrier.detach();
    options.signal?.addEventListener('abort', shut, { once: true });
    const socket = new WebSocketConnection(
      reader,
      carrier.writable,
      shut,
      chosen,
      options.maxMessageBytes ?? 16 * 1024 * 1024,
      deflate,
    );
    return { socket, headers };
  } catch (error) {
    shut();
    throw error;
  }
}
