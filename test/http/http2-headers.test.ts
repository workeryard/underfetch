import * as zlib from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { zlibDecoders } from '../../src/http/decompress';
import { http2Fetch } from '../../src/http/h2/connection';
import { encodeFrame, Flags, FrameType } from '../../src/http/h2/frames';
import { Hpack } from '../../src/http/h2/hpack';
import { data, framesIn, OK, serverHeaders, SETTINGS, socketOf } from './h2-peer';

describe('http2 headers and bodies', () => {
  it('writes headers in the order it is given, and states a known body length', async () => {
    const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
    await (
      await http2Fetch(
        socket,
        new Request('https://example.com/', {
          method: 'POST',
          body: '{"a":1}',
          headers: { 'user-agent': 'ua', accept: '*/*', 'content-type': 'application/json' },
        }),
        undefined,
        { headerOrder: ['content-length', 'user-agent', 'content-type', 'accept'] },
      )
    ).text();

    const block = framesIn(written).find((f) => f.type === FrameType.Headers);
    const names = new Hpack()
      .decode(block!.payload)
      .map(([name]) => name)
      .filter((name) => !name.startsWith(':'));
    expect(names).toEqual(['content-length', 'user-agent', 'content-type', 'accept']);
  });

  it('names itself when nobody set a user-agent, and only then', async () => {
    const sentHeaders = async (init?: RequestInit) => {
      const { socket, written } = socketOf([SETTINGS, OK, data('{}')]);
      await (await http2Fetch(socket, new Request('https://example.com/', init))).text();
      const block = framesIn(written).find((f) => f.type === FrameType.Headers);
      return new Hpack().decode(block!.payload).filter(([name]) => name === 'user-agent');
    };
    expect(await sentHeaders()).toEqual([['user-agent', 'underfetch/0.1']]);
    expect(await sentHeaders({ headers: { 'user-agent': 'my-worker/1.0' } })).toEqual([
      ['user-agent', 'my-worker/1.0'],
    ]);
  });

  it('undoes brotli with a decoder the runtime supplies', async () => {
    const packed = zlib.brotliCompressSync('{"ok":true}');
    const { socket } = socketOf([
      SETTINGS,
      serverHeaders(
        [
          [':status', '200'],
          ['content-encoding', 'br'],
        ],
        0,
      ),
      encodeFrame(FrameType.Data, Flags.EndStream, 1, new Uint8Array(packed)),
    ]);
    const response = await http2Fetch(socket, new Request('https://example.com/'), undefined, {
      decoders: zlibDecoders(zlib),
    });

    expect(response.headers.get('content-encoding')).toBeNull();
    expect(await response.json()).toEqual({ ok: true });
  });
});
