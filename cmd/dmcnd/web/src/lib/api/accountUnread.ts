// Reading another unlocked account's unread count, without becoming that account.
//
// Only possible because the tab holds live (non-extractable) handles for every
// account unlocked in it: the count is computed the same way the inbox badge is —
// mailbox headers decrypted in the browser, read/archived flags and the personal
// blocklist opened with that account's own key. The server sees three ordinary
// authenticated reads and no plaintext, exactly as it does for the active account.
//
// Each background account needs its own session token (the relay authorizes per
// account), minted silently from its unlocked signing key. Tokens are kept in memory
// only, for this tab, and re-minted on rejection.

import type { WorkingKeys } from '../crypto/workingKeys';
import { MailboxSync } from './mailboxRest';
import { FlagStore } from './flagStore';
import { deployment } from '@deployment';
import { loginWithKeys, ApiError } from './client';
import { countUnread } from '../unread';

const tokens = new Map<string, string>();

// Kept per account so the header cache survives across polls: an entry is immutable
// under its hash, so a steady-state poll re-decrypts nothing.
const syncs = new Map<string, MailboxSync>();

async function mintToken(address: string, wk: WorkingKeys): Promise<string> {
  const token = await loginWithKeys(address, wk.ed25519Sign);
  tokens.set(address, token);
  return token;
}

async function countWithToken(address: string, wk: WorkingKeys, token: string): Promise<number> {
  let sync = syncs.get(address);
  if (!sync) { sync = new MailboxSync(wk, () => { /* no subscribers */ }, token); syncs.set(address, sync); }
  const [previews, flags, filter] = await Promise.all([
    sync.list(),
    new FlagStore(wk, token).list(),
    // A missing/unreadable blocklist only means blocked senders aren't excluded —
    // not a reason to report no count at all.
    deployment.mailFilter(wk, token).get().catch(() => null),
  ]);
  return countUnread(previews, address, flags, filter);
}

// fetchAccountUnread returns the unread count for an account this tab holds unlocked
// but is not currently acting as. Rejects if the account can't be read.
export async function fetchAccountUnread(address: string, wk: WorkingKeys): Promise<number> {
  let token = tokens.get(address) ?? await mintToken(address, wk);
  try {
    return await countWithToken(address, wk, token);
  } catch (e) {
    // A cached token can outlive its session (expiry, or a sign-out elsewhere).
    // Explicit-token requests deliberately skip the global renewal handler, so the
    // one retry belongs here.
    if (!(e instanceof ApiError) || e.status !== 401) throw e;
    tokens.delete(address);
    syncs.delete(address);
    token = await mintToken(address, wk);
    return countWithToken(address, wk, token);
  }
}

// forgetAccountUnread drops an account's cached session + headers — on sign-out, or
// when it becomes the active account and the real mailbox sync takes over.
export function forgetAccountUnread(address: string): void {
  tokens.delete(address);
  syncs.delete(address);
}
