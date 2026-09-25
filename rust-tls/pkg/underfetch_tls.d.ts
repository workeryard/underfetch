/* tslint:disable */
/* eslint-disable */

/**
 * Session tickets, kept so a second connection to a host resumes the first
 * as a returning browser does. One per `Session` on the JavaScript side, so
 * nothing links one caller's connections to another's.
 *
 * rustls' own store also remembers which key-exchange group each server
 * chose and leads the next ClientHello's key share with it. A browser does
 * not — Chrome leads with X25519 every time — so that half is dropped here,
 * and only the tickets are kept.
 *
 * JavaScript holds the store by its `id`, which a `TlsClient` is handed;
 * wasm-bindgen cannot pass an optional reference to one of its own objects.
 * Dropping the store, which wasm-bindgen does when its JavaScript object is
 * collected, forgets the tickets.
 */
export class TicketStore {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Every TLS 1.3 ticket held, as bytes a later `import` takes back —
     * in another isolate, or after a deploy. Nothing is used up. TLS 1.2
     * sessions are not kept: they are rare now and their state is larger.
     *
     * These bytes resume sessions: keep them as a password is kept.
     */
    export(): Uint8Array;
    /**
     * Takes back what `export` wrote, and answers how many tickets were
     * usable. A ticket for a suite this build lacks is skipped; bytes of
     * another layout are refused whole.
     */
    import(blob: Uint8Array): number;
    constructor();
    readonly id: number;
}

export class TlsClient {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Starts a clean shutdown; the caller still has to flush `outgoing`.
     */
    close(): void;
    /**
     * The key exchange group the handshake settled on, as its TLS number —
     * 0x11ec for X25519MLKEM768, 0x001d for X25519. Meaningful once the
     * handshake is done.
     */
    keyExchangeGroup(): number | undefined;
    /**
     * A client that will accept only a certificate valid for `hostname`,
     * whatever address the underlying socket was opened to.
     *
     * The last three arguments shape the ClientHello, and come from the
     * caller rather than from here: adding a browser is then a table of
     * numbers in TypeScript instead of a rebuild of this crate. Leave them
     * out and rustls makes its own choices, which are safe and instantly
     * recognisable as rustls.
     */
    constructor(hostname: string, alpn?: string | null, ciphers?: Uint16Array | null, signature_schemes?: Uint16Array | null, extensions?: Uint8Array | null, grease_named_group?: boolean | null, extension_order?: Uint16Array | null, named_groups?: Uint16Array | null, intermediates?: Uint8Array | null, verifiable_signatures?: boolean | null, tickets?: number | null, key_shares?: Uint16Array | null);
    /**
     * Ciphertext waiting to go out on the socket. Empty when there is none.
     */
    outgoing(): Uint8Array;
    /**
     * Plaintext decrypted so far. Empty when the peer has sent nothing new.
     */
    plaintext(): Uint8Array;
    /**
     * The certificates the server sent, leaf first, as `(length u32, DER)`
     * records. Filled in when the chain is checked, whether or not it passed,
     * so a caller can look for the issuer a failed chain was missing.
     */
    presentedChain(): Uint8Array;
    /**
     * Hands over bytes that arrived from the network and returns how many were
     * taken. One call does not always consume the whole slice, so the caller
     * must loop from the returned offset or it will silently drop data.
     */
    receive(data: Uint8Array): number;
    /**
     * Whether this connection resumed an earlier session rather than doing
     * a full handshake. Meaningful once the handshake is done.
     */
    resumed(): boolean;
    /**
     * Queues plaintext for encryption; read it back out with `outgoing`.
     */
    send(data: Uint8Array): void;
    readonly handshaking: boolean;
    /**
     * The protocol the server picked from the ALPN list, if any.
     */
    readonly protocol: string | undefined;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_ticketstore_free: (a: number, b: number) => void;
    readonly __wbg_tlsclient_free: (a: number, b: number) => void;
    readonly ticketstore_export: (a: number, b: number) => void;
    readonly ticketstore_id: (a: number) => number;
    readonly ticketstore_import: (a: number, b: number, c: number, d: number) => void;
    readonly ticketstore_new: (a: number) => void;
    readonly tlsclient_close: (a: number) => void;
    readonly tlsclient_handshaking: (a: number) => number;
    readonly tlsclient_keyExchangeGroup: (a: number) => number;
    readonly tlsclient_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number, u: number, v: number) => void;
    readonly tlsclient_outgoing: (a: number, b: number) => void;
    readonly tlsclient_plaintext: (a: number, b: number) => void;
    readonly tlsclient_presentedChain: (a: number, b: number) => void;
    readonly tlsclient_protocol: (a: number, b: number) => void;
    readonly tlsclient_receive: (a: number, b: number, c: number, d: number) => void;
    readonly tlsclient_resumed: (a: number) => number;
    readonly tlsclient_send: (a: number, b: number, c: number, d: number) => void;
    readonly ring_core_0_17_14__bn_mul_mont: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number, d: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
