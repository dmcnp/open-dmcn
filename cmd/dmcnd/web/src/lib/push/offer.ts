// Whether to OFFER notifications to an account that has never answered the question.
//
// Turning them on lives in Settings → Account → Notifications, and for as long as that was the only
// way to hear of the feature, the people it was built for were the least likely to find it: someone
// who never opens Settings never learns their mail can reach them with the app closed. So the
// question is put once, on the inbox they have just unlocked, and then never again.
//
// Never again is the part that needs the care. The rules below are all reasons NOT to ask — asking
// twice is the failure mode this exists to avoid, and a notification prompt nobody asked for is the
// one that gets a site blocked at the browser for good.
//
// The answer is remembered in this browser rather than in the personal store, because what it
// answers is a question about this device: whether THIS browser, with its permission and its
// subscription, should wake for this mailbox. Declining on a borrowed laptop must not silence the
// question on the phone in your pocket, which is the device where it is worth a yes.

import { isDraftOpen } from '../draftOpen';
import { currentSubscription, pushSupported } from './subscription';

/** Where a given account's answer is remembered. Keyed by scope id, as everything here is. */
function answeredKey(id: string): string {
  return `dmcn_push_offered:${id}`;
}

/** The facts the decision is made on, gathered by {@link offerFacts}. */
export interface OfferFacts {
  /** This browser can receive notifications at all. */
  supported: boolean;
  /** Notifications are refused for this site, so subscribing cannot work and asking cannot help. */
  blocked: boolean;
  /** This account already holds a push subscription on this device. */
  subscribed: boolean;
  /** This account has been offered before and answered. */
  answered: boolean;
  /** An unsent message is open — someone is mid-sentence, not waiting to be asked something. */
  draftOpen: boolean;
}

/**
 * The decision itself, split from the browser it reads so it can be stated as rules and tested as
 * rules. Every clause is a reason not to ask.
 */
export function shouldOffer(f: OfferFacts): boolean {
  return f.supported && !f.blocked && !f.subscribed && !f.answered && !f.draftOpen;
}

/** Gather the facts for one account, by its push scope id. */
export async function offerFacts(id: string): Promise<OfferFacts> {
  const supported = pushSupported();
  return {
    supported,
    // 'default' (never asked) and 'granted' (asked on this origin, for some account) both still
    // allow a subscription. Only a refusal is final, and it is the browser's to reverse.
    blocked: typeof Notification !== 'undefined' && Notification.permission === 'denied',
    subscribed: supported && !!(await currentSubscription(id)),
    answered: offerAnswered(id),
    draftOpen: isDraftOpen(),
  };
}

/** Whether this account has already answered on this device. */
export function offerAnswered(id: string): boolean {
  try {
    return localStorage.getItem(answeredKey(id)) !== null;
  } catch {
    // No localStorage (private mode, blocked site data) means no memory of the answer. Reading it
    // as "not yet asked" is the wrong way to be wrong, so a browser that cannot remember is
    // treated as one that has already been asked.
    return true;
  }
}

/** Remember that this account answered, whichever way it went. */
export function rememberOfferAnswered(id: string): void {
  try {
    localStorage.setItem(answeredKey(id), '1');
  } catch {
    // Nothing to remember it with. The same failure makes offerAnswered read "asked", so the
    // question still does not come back.
  }
}
