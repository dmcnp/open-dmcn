import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { offerAnswered, offerFacts, rememberOfferAnswered, shouldOffer, type OfferFacts } from './offer';

// The inbox asks an account once whether it wants to be told about new mail. What is worth pinning
// is not the asking but the NOT asking: a notification prompt that comes back is the one a browser
// blocks for good, and every clause below is a reason someone must not be asked again.

// A localStorage stand-in; the module only ever reads and writes.
const store = new Map<string, string>();
beforeEach(() => {
  store.clear();
  vi.stubGlobal('localStorage', {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => { store.set(k, v); },
    removeItem: (k: string) => { store.delete(k); },
  });
});
afterEach(() => { vi.unstubAllGlobals(); });

const ID = '0123456789abcdef';

// Everything clear: a browser that can be notified, an account that holds no subscription and has
// never been asked, and nobody mid-sentence.
const CLEAR: OfferFacts = {
  supported: true, blocked: false, subscribed: false, answered: false, draftOpen: false,
};

describe('shouldOffer', () => {
  it('asks when nothing stands in the way', () => {
    expect(shouldOffer(CLEAR)).toBe(true);
  });

  it.each<[string, Partial<OfferFacts>]>([
    ['this browser cannot receive notifications at all', { supported: false }],
    ['the site is blocked, so a yes could not be honoured', { blocked: true }],
    ['this account is already subscribed on this device', { subscribed: true }],
    ['this account has answered before', { answered: true }],
    ['an unsent message is open', { draftOpen: true }],
  ])('stays quiet when %s', (_why, fact) => {
    expect(shouldOffer({ ...CLEAR, ...fact })).toBe(false);
  });
});

describe('the remembered answer', () => {
  it('is what turns the question off for that account', () => {
    expect(offerAnswered(ID)).toBe(false);
    rememberOfferAnswered(ID);
    expect(offerAnswered(ID)).toBe(true);
  });

  // Per account, like the subscription it is about: two mailboxes on one device each get asked.
  it('says nothing about another account', () => {
    rememberOfferAnswered(ID);
    expect(offerAnswered('fedcba9876543210')).toBe(false);
  });

  // A browser that cannot remember the answer would otherwise ask on every single unlock, which is
  // exactly the nag this must never become. Unreadable storage reads as "already asked".
  it('reads as asked when storage cannot be read', () => {
    vi.stubGlobal('localStorage', {
      getItem: () => { throw new Error('site data blocked'); },
      setItem: () => { throw new Error('site data blocked'); },
    });
    expect(offerAnswered(ID)).toBe(true);
    expect(() => rememberOfferAnswered(ID)).not.toThrow();
  });
});

// The facts are gathered from the browser, and there is no browser here — which is itself the
// answer to the only question a headless caller could ask.
describe('offerFacts', () => {
  it('offers nothing outside a browser', async () => {
    expect(shouldOffer(await offerFacts(ID))).toBe(false);
  });
});
