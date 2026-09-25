/** Anything that goes wrong on a WebSocket, from the handshake on. */
export class WebSocketError extends Error {
  override name = 'WebSocketError';
}
