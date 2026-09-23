/**
 * Just enough of `cloudflare:sockets` to open a connection.
 *
 * The full `@cloudflare/workers-types` would pull a second definition of
 * Request, Response and the streams into a package that is otherwise plain
 * TypeScript, and they collide with the DOM lib the tests run against. Three
 * members are all this adapter uses, so three members are all it declares.
 */
declare module 'cloudflare:sockets' {
  export interface Socket {
    readonly readable: ReadableStream<Uint8Array>;
    readonly writable: WritableStream<Uint8Array>;
    close(): Promise<void>;
  }

  export interface SocketAddress {
    hostname: string;
    port: number;
  }

  export function connect(address: SocketAddress): Socket;
}
