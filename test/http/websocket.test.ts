import { describe, expect, it } from 'vitest';
import { connectWebSocket, WebSocketRefused } from '../../src/client/websocket';
import { Session } from '../../src/client/session';
import { closeFrame, server, serverFrame, tls } from './ws-server';

describe('WebSocket', () => {
  it('upgrades, echoes text and bytes, and closes cleanly', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/chat?room=1', {
      dial: wire.dial,
      tls,
    });

    await socket.send('hello');
    expect(await socket.recv()).toEqual({ type: 'text', data: 'hello' });
    await socket.send(new Uint8Array([1, 2, 3]));
    expect(await socket.recv()).toEqual({ type: 'binary', data: new Uint8Array([1, 2, 3]) });

    expect(await socket.close(1000, 'bye')).toEqual({ code: 1000, reason: 'bye' });
    expect(wire.frames.every((f) => f.masked)).toBe(true);
    expect(wire.request()).toMatch(/^GET \/chat\?room=1 HTTP\/1.1\r\nHost: example.com\r\n/);
    expect(wire.request()).toContain('User-Agent: underfetch/0.1');
    expect(wire.request()).not.toContain('Sec-WebSocket-Extensions');
  });

  it('carries a message longer than one short frame', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });
    const big = 'x'.repeat(70_000);
    await socket.send(big);
    expect(wire.frames[0]?.payload.length).toBe(70_000);
    // The echo comes back with a 64-bit length, which the reader must follow.
    expect(await socket.recv()).toEqual({ type: 'text', data: big });
  });

  it('joins fragments, answering a ping that arrives between them', async () => {
    const wire = server({
      greeting: [
        serverFrame(0x1, 'hel', false),
        serverFrame(0x9, 'are you there'),
        serverFrame(0x0, 'lo', true),
      ],
    });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    expect(await socket.recv()).toEqual({ type: 'text', data: 'hello' });
    const pong = wire.frames.find((f) => f.op === 0xa);
    expect(new TextDecoder().decode(pong?.payload)).toBe('are you there');
  });

  it('answers a close the server starts, and then reads nothing more', async () => {
    const wire = server({ greeting: [serverFrame(0x1, 'last'), closeFrame(1001, 'going away')] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    const seen = [];
    for await (const message of socket) seen.push(message);
    expect(seen).toEqual([{ type: 'text', data: 'last' }]);
    expect(socket.closed).toEqual({ code: 1001, reason: 'going away' });
    const answer = wire.frames.find((f) => f.op === 0x8);
    expect([...(answer?.payload ?? [])]).toEqual([0x03, 0xe9]);
    await expect(socket.send('late')).rejects.toThrow(/closing/);
  });

  it('fails a masked server frame with 1002', async () => {
    const wire = server({ greeting: [serverFrame(0x1, 'sneaky', true, true)] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    await expect(socket.recv()).rejects.toThrow(/masked/);
    expect(socket.closed?.code).toBe(1002);
  });

  it('fails text that is not UTF-8 with 1007', async () => {
    const wire = server({ greeting: [serverFrame(0x1, new Uint8Array([0xff, 0xfe]))] });
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });

    await expect(socket.recv()).rejects.toThrow(/UTF-8/);
    expect(socket.closed?.code).toBe(1007);
  });

  it('fails a message over the limit with 1009', async () => {
    const wire = server({ greeting: [serverFrame(0x2, new Uint8Array(200))] });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      maxMessageBytes: 100,
    });

    await expect(socket.recv()).rejects.toThrow(/over the limit/);
    expect(socket.closed?.code).toBe(1009);
  });

  it('reports a connection that ends without a close as 1006', async () => {
    const wire = server();
    const { socket } = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls });
    wire.hangUp();

    expect(await socket.recv()).toBeNull();
    expect(socket.closed).toEqual({ code: 1006, reason: '' });
  });

  it('refuses a server that does not upgrade, keeping its status', async () => {
    const wire = server({ status: 403 });
    const error = await connectWebSocket('ws://example.com/', { dial: wire.dial, tls }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(WebSocketRefused);
    expect((error as WebSocketRefused).status).toBe(403);
  });

  it('refuses a subprotocol or an extension it never offered', async () => {
    for (const answerHeaders of [
      { 'Sec-WebSocket-Protocol': 'chat' },
      { 'Sec-WebSocket-Extensions': 'permessage-deflate' },
    ]) {
      const wire = server({ answerHeaders });
      await expect(connectWebSocket('ws://example.com/', { dial: wire.dial, tls })).rejects.toThrow(
        /never offered/,
      );
    }
  });

  it('accepts the subprotocol it offered', async () => {
    const wire = server({ answerHeaders: { 'Sec-WebSocket-Protocol': 'graphql-ws' } });
    const { socket } = await connectWebSocket('ws://example.com/', {
      dial: wire.dial,
      tls,
      protocols: ['graphql-ws', 'chat'],
    });
    expect(socket.protocol).toBe('graphql-ws');
    expect(wire.request()).toContain('Sec-WebSocket-Protocol: graphql-ws, chat');
  });
});

describe('Session.websocket', () => {
  it('sends the session headers a browser would, and its cookies, and keeps what it is set', async () => {
    const wire = server({ answerHeaders: { 'Set-Cookie': 'ws=1; Path=/' } });
    const session = new Session({
      dial: wire.dial,
      tls,
      cookies: true,
      headers: {
        'user-agent': 'Mozilla/5.0 test',
        'accept-language': 'en-US',
        'sec-fetch-mode': 'navigate',
        accept: 'text/html',
        'x-api-key': 'k',
      },
    });
    session.cookies?.store(new URL('http://example.com/'), ['sid=abc; Path=/']);

    const socket = await session.websocket('ws://example.com/live', {
      headers: { origin: 'http://example.com' },
    });
    const head = wire.request();
    expect(head).toContain('User-Agent: Mozilla/5.0 test');
    expect(head).toContain('Origin: http://example.com');
    expect(head).toContain('Accept-Language: en-US');
    expect(head).toContain('Cookie: sid=abc');
    expect(head).toContain('x-api-key: k');
    expect(head).not.toContain('sec-fetch-mode');
    expect(head).not.toMatch(/^accept:/im);
    // The Chrome order: Connection before User-Agent, Upgrade after it.
    expect(head.indexOf('Connection: Upgrade')).toBeLessThan(head.indexOf('User-Agent'));
    expect(head.indexOf('User-Agent')).toBeLessThan(head.indexOf('Upgrade: websocket'));
    expect(session.cookies?.header(new URL('http://example.com/'))).toContain('ws=1');
    await socket.close();
  });
});
