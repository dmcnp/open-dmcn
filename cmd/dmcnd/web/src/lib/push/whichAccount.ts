// Which of this device's accounts a notification was about.
//
// The worker says only a scope id, and the id is a hash of the account's X25519 public key — the
// same key the relay names the mailbox by. So the answer is derived rather than looked up: each
// candidate's id is recomputed and compared, which means there is no index that could drift out of
// step with the registrations.
//
// It works while every account is LOCKED, which is the case that matters: a notification for a
// closed app is tapped long after the handles are gone. The keystore holds the public half in the
// clear for exactly this kind of question — identifying an account without decrypting it.
//
// Not in scopes.ts, and not for style: accounts.ts imports scopes.ts, so the dependency has to run
// this way round.

import { listDeviceAccounts, type DeviceAccount } from '../accounts';
import { fromBase64 } from '../crypto/keys';
import { scopeIdFor } from './scopes';

export async function accountForScope(id: string): Promise<DeviceAccount | null> {
  for (const account of await listDeviceAccounts()) {
    if (!account.ks) continue; // a temporary session has no at-rest key to derive from
    try {
      if (await scopeIdFor(fromBase64(account.ks.x25519Public)) === id) return account;
    } catch { /* a malformed record is not the account we are looking for */ }
  }
  return null;
}
