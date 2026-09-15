// Withdrawing this mailbox's notifications as part of signing out.
//
// Two rules make this less obvious than it looks.
//
// It must run BEFORE the keys and session are dropped: withdrawing is an authenticated mailbox op,
// signed by the account's own key. A moment later there is nothing left to sign with.
//
// And it must never call `subscription.unsubscribe()`. A browser holds ONE push endpoint, shared by
// every account signed into it, so dropping it at the browser would silently stop notifications for
// someone else who is still signed in. Withdrawing is scoped to this mailbox; the browser keeps its
// subscription, and the endpoint simply stops being registered against this account.
//
// Failure is never allowed to block signing out. Someone leaving a shared machine must leave.

import { deployment } from '@deployment';
import type { WorkingKeys } from '../crypto/workingKeys';
import { currentSubscription, forgetEndpoint, pushSupported } from './subscription';

export async function withdrawPushOnSignOut(address: string, keys: WorkingKeys | null): Promise<void> {
  if (!deployment.push || !pushSupported() || !address || !keys) return;
  try {
    const sub = await currentSubscription();
    if (sub) await deployment.push.unregister(address, sub.endpoint, keys);
    forgetEndpoint(address);
  } catch {
    // The row expires on its own, and anything it might send says only "New mail".
  }
}
