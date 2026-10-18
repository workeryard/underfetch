import { describe, expect, it } from 'vitest';
import { refused } from '../../src/workers/refused';

describe('a refused connection', () => {
  it('is the Cloudflare block, for good, only when production says so', () => {
    const block = refused(
      'example.com',
      443,
      new Error(
        'proxy request failed, cannot connect to the specified address. It looks like you might be trying to connect to a HTTP-based service — consider using fetch instead',
      ),
    );
    expect(block.permanent).toBe(true);
    expect(block.message).toMatch(/Cloudflare's own IP ranges/);
  });

  it('may work on another try otherwise, a cancelled stream included', () => {
    for (const said of [
      'Stream was cancelled.',
      'proxy request failed, cannot connect to the specified address',
      'connection refused',
    ]) {
      const error = refused('tls.peet.ws', 443, new Error(said));
      expect(error.permanent, said).toBe(false);
      expect(error.message, said).not.toMatch(/Cloudflare/);
    }
  });
});
