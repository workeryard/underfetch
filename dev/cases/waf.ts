/**
 * Sites behind a bot manager that lets a request through on its fingerprint
 * alone, taken from wafer's benchmark (Tier 1 and Tier 2 of
 * github.com/Averyy/wafer/blob/main/docs/site-list.md). wafer passes each of
 * them with BoringSSL's own handshake, so a failure here is a gap in ours.
 *
 * Four fail from any machine outside North America, whatever sends the
 * request — plain curl included: car.gr and DraftKings answer 403, Costco 404,
 * and kroger.com does not resolve. Read those as the vantage point, not the
 * fingerprint.
 *
 * Each site is also fetched with the platform's `fetch`, which impersonates
 * nothing: where that fails and a profile passes, the profile is what made
 * the difference.
 */

import { Session, type WorkerSessionDefaults } from '../../src/workers/index';
import { run, type Outcome } from './probe';

const SITES: readonly (readonly [url: string, guard: string])[] = [
  ['https://www.ticketmaster.com/', 'Akamai, lenient'],
  ['https://www.nytimes.com/', 'minimal'],
  ['https://www.vinted.com/', 'Cloudflare'],
  ['https://www.car.gr/', 'Cloudflare'],
  ['https://sportsbook.draftkings.com/', 'Cloudflare'],
  ['https://www.nbcsports.com/', 'Cloudflare'],
  ['https://www.aircanada.com/', 'Akamai'],
  ['https://www.crateandbarrel.com/', 'Akamai'],
  ['https://www.nike.com/', 'Akamai'],
  ['https://www.ebay.com/', 'Akamai'],
  ['https://www.delta.com/', 'Akamai'],
  ['https://www.costco.com/', 'Akamai'],
  ['https://www.kroger.com/', 'Akamai'],
  ['https://www.samsclub.com/', 'Akamai'],
  ['https://stockx.com/', 'PerimeterX'],
  ['https://www.digikey.com/', 'PerimeterX + Cloudflare'],
  ['https://weedmaps.com/', 'PerimeterX'],
  ['https://www.asda.com/', 'PerimeterX'],
  ['https://www.traveloka.com/', 'AWS WAF'],
  ['https://www.similarweb.com/', 'AWS WAF'],
  ['https://www.whoscored.com/', 'Imperva'],
  ['https://www.psacard.com/', 'Imperva'],
  ['https://www.marketwatch.com/', 'DataDome'],
  ['https://www.godaddy.com/', 'Kasada'],
  ['https://arcteryx.com/', 'Kasada'],
  ['https://www.chase.com/', 'Shape'],
];

/** What an interstitial says about itself, looked for only in a small body. */
const CHALLENGE =
  /just a moment|cf-chl-|px-captcha|captcha-delivery|_Incapsula_Resource|Pardon Our Interruption|Access Denied|awswaf|KPSDK|sec-if-cpt-container|verify you are human/i;

interface Seen {
  status: number;
  bytes: number;
  challenged: boolean;
}

async function look(response: Response): Promise<Seen> {
  const text = await response.text();
  // A real page may carry a bot manager's script; only a page that is little
  // else is taken for an interstitial.
  const challenged = response.status >= 400 || (text.length < 30_000 && CHALLENGE.test(text));
  return { status: response.status, bytes: text.length, challenged };
}

const show = (seen: Seen | string) =>
  typeof seen === 'string'
    ? seen
    : `${seen.status} ${Math.round(seen.bytes / 1024)}KB${seen.challenged ? ' BLOCKED' : ''}`;

export async function wafCases(profile: WorkerSessionDefaults['impersonate']) {
  const out: Outcome[] = [];
  for (const [url, guard] of SITES) {
    out.push(
      await run('waf', `${guard}: ${new URL(url).hostname}`, async () => {
        const ours = await new Session({ timeoutMs: 20_000, retry: false, impersonate: profile })
          .get(url)
          .then(look);
        const platform = await fetch(url, { signal: AbortSignal.timeout(20_000) })
          .then(look)
          .catch((error: unknown) => `threw ${String(error).slice(0, 40)}`);
        return [!ours.challenged, `underfetch ${show(ours)} | platform fetch ${show(platform)}`];
      }),
    );
  }
  return out;
}
