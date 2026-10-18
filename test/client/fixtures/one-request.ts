// One request through a session that keeps its connection, then nothing:
// the process should end once the answer is printed, not 60 s later when
// the connection's idle timer would fire.
import { Session } from '../../../src/client/session';
import { http1Server, ok } from '../pool-peers';

const server = http1Server(() => ok('answered'));
const session = new Session({
  dial: server.dial,
  tls: () => {
    throw new Error('plain http');
  },
});
console.log(await (await session.get('http://example.com/')).text());
