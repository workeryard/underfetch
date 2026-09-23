/**
 * Logging in, the way a person would, against public practice sites. Each
 * flow checks both halves: that the session opens the door, and that without
 * it the door stays shut — a case that passed with no cookie at all would
 * prove nothing.
 */

import { Session, type WorkerSessionDefaults } from '../../src/workers/index';
import { run, type Check, type Outcome } from './probe';

type Profile = WorkerSessionDefaults['impersonate'];

const session = (profile: Profile) =>
  new Session({ timeoutMs: 20_000, retry: false, impersonate: profile, cookies: true });

/** A classic form login: POST, a 302, and a session cookie. */
async function formLogin(profile: Profile): Promise<[boolean, string]> {
  const base = 'https://the-internet.herokuapp.com';

  const stranger = await session(profile).get(`${base}/secure`);
  const strangerPage = await stranger.text();
  const shut = stranger.url.endsWith('/login') && !strangerPage.includes('Secure Area');

  const user = session(profile);
  const wrong = await user.post(`${base}/authenticate`, {
    form: { username: 'tomsmith', password: 'wrong' },
  });
  const refused = (await wrong.text()).includes('Your password is invalid');

  const login = await user.post(`${base}/authenticate`, {
    form: { username: 'tomsmith', password: 'SuperSecretPassword!' },
  });
  const inside = (await login.text()).includes('Secure Area') && login.url.endsWith('/secure');
  const again = (await (await user.get(`${base}/secure`)).text()).includes('Secure Area');

  const logout = await user.get(`${base}/logout`);
  await logout.text();
  const after = await user.get(`${base}/secure`);
  const out = !(await after.text()).includes('Secure Area');

  const cookies = user.cookies?.all().map((c) => c.name) ?? [];
  return [
    shut && refused && inside && again && out,
    `no login shut=${shut}, wrong password refused=${refused}, logged in=${inside}, ` +
      `stays in=${again}, logout shuts=${out}; cookies ${cookies.join(',')}`,
  ];
}

/** A form carrying a CSRF token that must be read from the page first. */
async function csrfLogin(profile: Profile): Promise<[boolean, string]> {
  const base = 'https://quotes.toscrape.com';
  const user = session(profile);

  const form = await (await user.get(`${base}/login`)).text();
  const token = /name="csrf_token" value="([^"]+)"/.exec(form)?.[1];
  if (token === undefined) return [false, 'no csrf_token on the login page'];

  // A wrong token, not a missing one: this site lets a form with no token at
  // all through, which curl confirms, so only a wrong one tests anything.
  const forged = session(profile);
  await (await forged.get(`${base}/login`)).text();
  const bogus = await forged.post(`${base}/login`, {
    form: { csrf_token: 'forged', username: 'ada', password: 'lovelace' },
  });
  const forgedIn = (await bogus.text()).includes('Logout');

  const login = await user.post(`${base}/login`, {
    form: { csrf_token: token, username: 'ada', password: 'lovelace' },
  });
  const inside = (await login.text()).includes('Logout');
  const again = (await (await user.get(`${base}/page/2/`)).text()).includes('Logout');

  return [
    !forgedIn && inside && again,
    `token read=${token.length} chars, forged token let in=${forgedIn}, ` +
      `with token logged in=${inside}, next page still in=${again}`,
  ];
}

/** A JSON API: credentials in, a token and a cookie out, then who am I. */
async function apiLogin(profile: Profile): Promise<[boolean, string]> {
  const base = 'https://dummyjson.com';

  const anonymous = await session(profile).get(`${base}/auth/me`);
  await anonymous.text();

  const user = session(profile);
  const login = await user.post(`${base}/auth/login`, {
    json: { username: 'emilys', password: 'emilyspass', expiresInMins: 5 },
  });
  const body = (await login.json()) as { accessToken?: string; username?: string };
  const token = body.accessToken;
  if (token === undefined) return [false, `login answered ${login.status} without a token`];

  // The server set the token as a cookie too, so the jar alone should do.
  const byCookie = await user.get(`${base}/auth/me`);
  const cookieUser = ((await byCookie.json()) as { username?: string }).username;

  const byBearer = await session(profile).get(`${base}/auth/me`, { auth: { bearer: token } });
  const bearerUser = ((await byBearer.json()) as { username?: string }).username;

  return [
    anonymous.status === 401 && cookieUser === 'emilys' && bearerUser === 'emilys',
    `anonymous ${anonymous.status}, login ${login.status}, ` +
      `by cookie=${cookieUser ?? byCookie.status}, by bearer=${bearerUser ?? byBearer.status}`,
  ];
}

export async function sessionCases(profile: Profile) {
  const out: Outcome[] = [];
  const add = async (name: string, check: Check) => out.push(await run('session', name, check));
  await add('form login, session cookie, logout', () => formLogin(profile));
  await add('login behind a CSRF token', () => csrfLogin(profile));
  await add('JSON API login, cookie and bearer', () => apiLogin(profile));
  return out;
}
