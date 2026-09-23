/** Buffered reading over a byte stream: the shape every wire protocol needs. */

const CR = 13;
const LF = 10;

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  if (left.length === 0) return right;
  const joined = new Uint8Array(left.length + right.length);
  joined.set(left);
  joined.set(right, left.length);
  return joined;
}

/**
 * Reads a stream a field at a time. A protocol parser asks for exact byte
 * counts or CRLF-terminated lines; whatever is left over when the headers end
 * belongs to the body, so `rest()` hands the remainder back as a stream.
 */
export class ByteReader {
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;
  #buffer: Uint8Array = new Uint8Array(0);
  #ended = false;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.#reader = stream.getReader();
  }

  /** Pulls one more chunk into the buffer. False once the stream is spent. */
  async #pull(): Promise<boolean> {
    if (this.#ended) return false;
    const { value, done } = await this.#reader.read();
    if (done) {
      this.#ended = true;
      return false;
    }
    if (value && value.length > 0) this.#buffer = concat(this.#buffer, value);
    return true;
  }

  #take(length: number): Uint8Array {
    const taken = this.#buffer.subarray(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return taken;
  }

  /** Exactly `length` bytes, or an error naming how short the stream fell. */
  async exactly(length: number): Promise<Uint8Array> {
    while (this.#buffer.length < length) {
      if (!(await this.#pull())) {
        throw new Error(`stream ended after ${this.#buffer.length} of ${length} bytes`);
      }
    }
    return this.#take(length);
  }

  async byte(): Promise<number> {
    return (await this.exactly(1))[0] ?? 0;
  }

  /**
   * Whatever has arrived, up to `max`, waiting only for the first byte. A body
   * is forwarded with this rather than `exactly`, which would hold a streamed
   * answer back until a full buffer's worth of it existed.
   */
  async some(max: number): Promise<Uint8Array | null> {
    while (this.#buffer.length === 0) {
      if (!(await this.#pull())) return null;
    }
    return this.#take(Math.min(max, this.#buffer.length));
  }

  /**
   * One CRLF-terminated line, without the terminator. `limit` keeps a peer that
   * never sends one from growing the buffer without end.
   */
  async line(limit = 16_384): Promise<string> {
    for (let from = 0; ;) {
      for (let i = from; i + 1 < this.#buffer.length; i++) {
        if (this.#buffer[i] === CR && this.#buffer[i + 1] === LF) {
          const line = this.#take(i);
          this.#take(2);
          return new TextDecoder().decode(line);
        }
      }
      // Re-scanning from the last byte of the previous pass, minus the CR that
      // may straddle the boundary, keeps this linear in the line's length.
      from = Math.max(0, this.#buffer.length - 1);
      if (this.#buffer.length > limit) throw new Error('line longer than the limit');
      if (!(await this.#pull())) throw new Error('stream ended inside a line');
    }
  }

  /** Everything not yet consumed, buffer first, then the rest of the stream. */
  rest(): ReadableStream<Uint8Array> {
    const buffered = this.#buffer;
    this.#buffer = new Uint8Array(0);
    const reader = this.#reader;
    const ended = this.#ended;
    return new ReadableStream<Uint8Array>({
      start(controller) {
        if (buffered.length > 0) controller.enqueue(buffered);
        if (ended) controller.close();
      },
      async pull(controller) {
        if (ended) return;
        const { value, done } = await reader.read();
        if (done) controller.close();
        else if (value) controller.enqueue(value);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    });
  }
}

/** Writes whole frames to a stream, one protocol step at a time. */
export class ByteWriter {
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;

  constructor(stream: WritableStream<Uint8Array>) {
    this.#writer = stream.getWriter();
  }

  write(bytes: Uint8Array): Promise<void> {
    return this.#writer.write(bytes);
  }

  release(): void {
    this.#writer.releaseLock();
  }
}
