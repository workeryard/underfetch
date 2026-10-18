/**
 * HTTP/2 over a socket we opened ourselves, as many requests at a time as
 * the server allows.
 *
 * One loop reads every frame and hands each to its stream; requests write
 * their own HEADERS and DATA. What is left out is what a client may leave
 * out: server push (refused in our SETTINGS), a priority tree, and PRIORITY
 * frames, which no browser profile here sends.
 *
 * The settings we send are part of the fingerprint — a browser is as
 * recognisable by its SETTINGS frame as by its ClientHello — so they come from
 * the caller rather than from here.
 */

import { ByteReader, ByteWriter } from '../../net/bytes';
import { Hpack } from './hpack';
import {
  decodeSettings,
  encodeFrame,
  encodeRstStream,
  encodeSettings,
  ErrorCode,
  encodeWindowUpdate,
  errorName,
  Flags,
  FrameType,
  Http2Error,
  PREFACE,
  type Frame,
  readFrame,
  Setting,
  unpad,
} from './frames';
import { DEFAULT_MAX_FRAME, DEFAULT_WINDOW, ReceiveWindows } from './flow';
import {
  DEFAULT_PROFILE,
  joined,
  outgoing,
  type Http2ConnectionOptions,
  type Http2Options,
  type Http2Profile,
  type Http2RequestOptions,
  type Http2Socket,
} from './request';
import { Http2Stream, type StreamHost } from './stream';

export { DEFAULT_PROFILE } from './request';
export type { Http2Options, Http2Profile, Http2RequestOptions } from './request';

/** Stream identifiers are 31 bits, and a client's are odd. */
const LAST_STREAM = 2 ** 31 - 1;

/**
 * An HTTP/2 connection: the preface and SETTINGS go out as it is made, and
 * each `request` opens a stream of its own on it.
 */
export class Http2Connection {
  readonly #writer: ByteWriter;
  readonly #reader: ByteReader;
  /** Decodes the server's header blocks; its table spans every response. */
  readonly #hpack = new Hpack();
  readonly #profile: Http2Profile;
  readonly #options: Http2ConnectionOptions;
  readonly #streams = new Map<number, Http2Stream>();
  readonly #host: StreamHost;
  #nextId = 1;

  // What the server allows us: its frame size, its streams, its windows.
  #maxFrame = DEFAULT_MAX_FRAME;
  #maxStreams = Infinity;
  #initialWindow = DEFAULT_WINDOW;
  #window = DEFAULT_WINDOW;

  /** What we granted the server, and what of it has been read. */
  readonly #received: ReceiveWindows;
  /** The largest frame we said we would read. */
  readonly #readLimit: number;

  /** A header block still waiting for its CONTINUATION frames. */
  #block: { stream: number; parts: Uint8Array[]; endStream: boolean } | undefined;
  /** The last stream a GOAWAY promised to finish. */
  #goaway: number | undefined;
  #failure: Error | undefined;

  constructor(
    socket: Http2Socket,
    profile: Http2Profile = DEFAULT_PROFILE,
    options: Http2ConnectionOptions = {},
  ) {
    this.#writer = new ByteWriter(socket.writable);
    this.#reader = new ByteReader(socket.readable);
    this.#profile = profile;
    this.#options = options;
    const setting = (id: number) => profile.settings.find(([known]) => known === id)?.[1];
    this.#readLimit = setting(Setting.MaxFrameSize) ?? DEFAULT_MAX_FRAME;
    this.#received = new ReceiveWindows(
      setting(Setting.InitialWindowSize) ?? DEFAULT_WINDOW,
      DEFAULT_WINDOW + profile.windowUpdate,
      (frame) => this.#post(frame),
    );
    // The streams' view of the connection, without handing them all of it.
    this.#host = {
      maxFrame: () => this.#maxFrame,
      window: () => this.#window,
      spend: (bytes) => void (this.#window -= bytes),
      write: (frame) => this.#write(frame),
      consumed: (stream, cost) => this.#received.consumed(stream, cost),
      settle: (stream) => this.#settle(stream),
      cancel: (stream, reason) => this.#cancel(stream, reason),
    };

    void this.#write(PREFACE);
    void this.#write(encodeFrame(FrameType.Settings, 0, 0, encodeSettings(profile.settings)));
    if (profile.windowUpdate > 0) {
      void this.#write(
        encodeFrame(FrameType.WindowUpdate, 0, 0, encodeWindowUpdate(profile.windowUpdate)),
      );
    }
    void this.#loop();
  }

  /** Whether a request may start on it now. */
  get available(): boolean {
    return this.alive && this.#streams.size < this.#maxStreams;
  }

  /** Whether it will ever take another request. */
  get alive(): boolean {
    return this.#failure === undefined && this.#goaway === undefined && this.#nextId <= LAST_STREAM;
  }

  /** Hangs up: every open stream fails, and the socket is closed. */
  close(reason: Error = new Http2Error('the connection was closed')): void {
    this.#fail(reason);
  }

  /**
   * Sends `request` on a stream of its own and returns the answer with its
   * body still streaming.
   */
  async request(request: Request, options: Http2RequestOptions = {}): Promise<Response> {
    if (!this.available) throw new Http2Error('the connection takes no more requests', true);
    const { streamBody = false, decoders = {}, headerOrder, signal } = options;
    const profile = options.profile ?? this.#profile;

    // Registered before anything is awaited, so no frame for it is missed.
    const stream = new Http2Stream(this.#nextId, this.#initialWindow, decoders);
    this.#nextId += 2;
    this.#streams.set(stream.id, stream);
    if (signal !== undefined) {
      const abort = () => this.#cancel(stream, signal.reason as Error);
      if (signal.aborted) abort();
      signal.addEventListener('abort', abort, { once: true });
      stream.unlisten = () => signal.removeEventListener('abort', abort);
    }

    try {
      const { body, frames } = await outgoing(request, stream.id, profile, {
        streamBody,
        headerOrder,
        maxFrame: this.#maxFrame,
      });
      if (stream.error !== undefined) return await stream.answer;
      if (body === null) stream.sentEnd = true;
      try {
        await this.#writer.write(frames);
      } catch (error) {
        // Nothing reached the server, so nothing was acted on: this stream
        // learns that before the rest learn the connection is gone.
        const lost = 'the connection was lost before the request went out';
        this.#streamError(stream, new Http2Error(lost, true, { cause: error }));
        this.#fail(error as Error);
      }
      if (body !== null) void stream.upload(this.#host, body);
    } catch (error) {
      this.#streamError(stream, error as Error);
    }
    return stream.answer;
  }

  async #write(bytes: Uint8Array): Promise<void> {
    try {
      await this.#writer.write(bytes);
    } catch (error) {
      this.#fail(error as Error);
      throw error;
    }
  }

  /** Frames that need not be waited on: acknowledgements and window updates. */
  #post(bytes: Uint8Array): void {
    if (this.#failure === undefined) this.#write(bytes).catch(() => undefined);
  }

  async #loop(): Promise<void> {
    try {
      for (;;) this.#dispatch(await readFrame(this.#reader, this.#readLimit));
    } catch (error) {
      this.#fail(
        error instanceof Http2Error
          ? error
          : new Http2Error('the connection was lost', false, { cause: error }),
      );
    }
  }

  #dispatch(frame: Frame): void {
    if (this.#block !== undefined) {
      if (frame.type !== FrameType.Continuation || frame.stream !== this.#block.stream) {
        throw new Http2Error('the server interrupted a header block');
      }
      this.#block.parts.push(frame.payload);
      if ((frame.flags & Flags.EndHeaders) !== 0) {
        const { stream, parts, endStream } = this.#block;
        this.#block = undefined;
        this.#headers(stream, joined(parts), endStream);
      }
      return;
    }
    const view = new DataView(frame.payload.buffer, frame.payload.byteOffset);
    const word = (at: number) => (frame.payload.length >= at + 4 ? view.getUint32(at) : 0);
    const stream = this.#streams.get(frame.stream);

    switch (frame.type) {
      case FrameType.Settings:
        if ((frame.flags & Flags.Ack) === 0) this.#settings(frame.payload);
        return;
      case FrameType.Ping:
        if ((frame.flags & Flags.Ack) === 0) {
          this.#post(encodeFrame(FrameType.Ping, Flags.Ack, 0, frame.payload));
        }
        return;
      case FrameType.GoAway:
        this.#goAway(word(0) & 0x7fffffff, word(4));
        return;
      case FrameType.WindowUpdate: {
        const increment = word(0) & 0x7fffffff;
        if (frame.stream === 0) {
          this.#window += increment;
          for (const open of this.#streams.values()) open.nudge();
        } else if (stream !== undefined) {
          stream.send += increment;
          stream.nudge();
        }
        return;
      }
      case FrameType.Headers: {
        const piece = unpad(frame.payload, frame.flags, true);
        const endStream = (frame.flags & Flags.EndStream) !== 0;
        if ((frame.flags & Flags.EndHeaders) !== 0) this.#headers(frame.stream, piece, endStream);
        else this.#block = { stream: frame.stream, parts: [piece], endStream };
        return;
      }
      case FrameType.Continuation:
        throw new Http2Error('the server sent a CONTINUATION with no header block before it');
      case FrameType.Data:
        // The window is spent on the padded length, not what survives it.
        if (stream === undefined || !stream.answered) {
          // A stream we have let go of still used up the connection's window.
          this.#received.consumed(undefined, frame.payload.length);
          return;
        }
        stream.data(unpad(frame.payload, frame.flags, false), frame.payload.length);
        if ((frame.flags & Flags.EndStream) !== 0) this.#end(stream);
        return;
      case FrameType.RstStream: {
        if (stream === undefined) return;
        const code = word(0);
        // A reset with no error after a whole answer only stops our upload.
        if (code === ErrorCode.NoError && stream.ended) {
          stream.nudge();
          return;
        }
        const why = `the server reset the stream: ${errorName(code)}`;
        this.#streamError(stream, new Http2Error(why, code === ErrorCode.RefusedStream));
        return;
      }
      case FrameType.PushPromise:
        // Push is off in every profile's SETTINGS, so a server sending one
        // has broken the protocol, and its header block would put our HPACK
        // table out of step.
        throw new Http2Error('the server pushed a stream, which our SETTINGS refused');
      default:
        // PRIORITY and anything newer: nothing for a client to do.
        return;
    }
  }

  #settings(payload: Uint8Array): void {
    const settings = decodeSettings(payload);
    this.#maxFrame = settings.get(Setting.MaxFrameSize) ?? this.#maxFrame;
    this.#maxStreams = settings.get(Setting.MaxConcurrentStreams) ?? this.#maxStreams;
    const window = settings.get(Setting.InitialWindowSize);
    if (window !== undefined) {
      // A new initial size moves every open stream's window by the difference.
      const change = window - this.#initialWindow;
      this.#initialWindow = window;
      for (const stream of this.#streams.values()) {
        stream.send += change;
        stream.nudge();
      }
    }
    this.#post(encodeFrame(FrameType.Settings, Flags.Ack, 0, new Uint8Array(0)));
  }

  #goAway(last: number, code: number): void {
    this.#goaway = Math.min(last, this.#goaway ?? LAST_STREAM);
    // Streams up to `last` are still answered; the server never saw the rest.
    for (const stream of [...this.#streams.values()]) {
      if (stream.id <= last) continue;
      const why = `the server closed the connection: ${errorName(code)}`;
      this.#streamError(stream, new Http2Error(why, true));
    }
    if (this.#streams.size === 0) this.close();
  }

  #headers(id: number, block: Uint8Array, endStream: boolean): void {
    // Decoded whatever stream it is for: the table is the connection's.
    const headers = this.#hpack.decode(block);
    const stream = this.#streams.get(id);
    if (stream?.headers(this.#host, headers, endStream) === true && endStream) this.#end(stream);
  }

  #end(stream: Http2Stream): void {
    stream.end();
    this.#settle(stream);
  }

  /** Lets go of a stream both sides are done with. */
  #settle(stream: Http2Stream): void {
    if (!stream.ended || !stream.drained || stream.sending) return;
    if (!stream.sentEnd) {
      // The server answered before the body was all sent: our half is closed
      // with a reset that says nothing went wrong.
      this.#post(encodeRstStream(stream.id, ErrorCode.NoError));
      stream.sentEnd = true;
    }
    this.#forget(stream);
  }

  /** Our side gives up on a stream; the connection carries on. */
  #cancel(stream: Http2Stream, reason: Error): void {
    if (!this.#streams.has(stream.id)) return;
    if (!(stream.ended && stream.sentEnd)) this.#post(encodeRstStream(stream.id, ErrorCode.Cancel));
    this.#streamError(stream, reason);
  }

  /** Fails one stream: its answer if not given yet, else its body. */
  #streamError(stream: Http2Stream, error: Error): void {
    if (stream.error !== undefined) return;
    stream.fail(error);
    this.#forget(stream);
  }

  #forget(stream: Http2Stream): void {
    stream.unlisten();
    if (!this.#streams.delete(stream.id) || this.#streams.size > 0) return;
    if (this.#goaway !== undefined) this.close();
    else this.#options.onIdle?.();
  }

  #fail(error: Error): void {
    if (this.#failure !== undefined) return;
    this.#failure = error;
    for (const stream of [...this.#streams.values()]) this.#streamError(stream, error);
    this.#options.close?.();
  }
}

/**
 * One request on a connection of its own. `socket` is spent afterwards, and
 * closing it is the caller's job.
 */
export function http2Fetch(
  socket: Http2Socket,
  request: Request,
  profile: Http2Profile = DEFAULT_PROFILE,
  options: Http2Options = {},
): Promise<Response> {
  return new Http2Connection(socket, profile).request(request, options);
}
