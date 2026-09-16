// Turning notifications on for one account on this device: the whole act, in one place.
//
// Two screens perform it — the settings card, and the offer a newly unlocked mailbox is greeted
// with — and it is not a sequence either of them should be holding its own copy of. The order
// matters (a subscription the relay never heard of is a browser waiting for a wake-up that will
// never come) and so does the failure path: the registration is created BEFORE it can be known
// whether a subscription is obtainable, and nothing else in the app would ever sweep up the one
// left behind by a failure — the load-time sweep deliberately only touches registrations that once
// had a subscription and lost it.
//
// The one deployment-specific step is where the endpoint gets registered, which is why this is not
// in subscription.ts: that file stays free of the seam so the browser half can be reasoned about
// on its own.

import { deployment } from '@deployment';
import type { WorkingKeys } from '../crypto/workingKeys';
import { scopeIdFor, tearDownScope } from './scopes';
import { rememberEndpoint, subscribeAccount } from './subscription';

/**
 * Ask permission, subscribe this account, and hand the endpoint to the deployment.
 *
 * Must be called from a click: Safari requires a user gesture for the permission prompt. Returns
 * the account's scope id; throws with a message fit to show if any step refuses.
 */
export async function enableNotifications(address: string, keys: WorkingKeys): Promise<string> {
  const id = await scopeIdFor(keys.x25519Public);
  try {
    const sub = await subscribeAccount(id, deployment.push!.workerUrl);
    await deployment.push!.register(address, sub.endpoint, keys);
    rememberEndpoint(address, sub.endpoint);
    return id;
  } catch (e) {
    await tearDownScope(id).catch(() => { /* best effort */ });
    throw e;
  }
}
