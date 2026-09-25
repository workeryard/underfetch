/**
 * Just enough of `cloudflare:sockets` to open a connection.
 *
 * The full `@cloudflare/workers-types` would pull a second definition of
 * Request, Response and the streams into a package that is otherwise plain
 * TypeScript, and they collide with the DOM lib the tests run against. What
 * this adapter uses is all it declares.
 */
declare module 'cloudflare:sockets' {
  export interface Socket {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
    close(): Promise<void>;
    /** Settles once the connection is up, or rejects when it cannot be made. */
    readonly opened: Promise<unknown>;
  }

  export interface SocketAddress {
    hostname: string;
    port: number;
  }

  export function connect(address: SocketAddress): Socket;
}
