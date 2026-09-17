// Which accounts have been woken by a notification since anyone last looked at them.
//
// The mark is written by the notification worker into its cache, named by scope id. Reading it here
// rather than tracking it in the app is what makes it survive the app being closed entirely, which
// is the only case that matters: if the app had been open, the mail would already be on screen.
//
// Deliberately nothing but a set of addresses. The worker knows no more than "something arrived for
// this mailbox", so neither does this.

import { useEffect, useState } from 'react';
import type { DeviceAccount } from '../accounts';
import { fromBase64 } from '../crypto/keys';
import { scopeIdFor } from './scopes';
import { wasWoken } from './subscription';

// What an account has to offer to be asked about: its address, and the public half the scope id is
// derived from. Two fields rather than a DeviceAccount, because the other caller is an unlock
// holding freshly imported handles and has no reason to go back to IndexedDB for records it is
// already looking at.
export interface WokenCandidate {
  address: string;
  x25519Public: Uint8Array;
}

// wokenAddresses answers for a set of candidates at once. This is the whole mechanism; the hook
// below is only the shell that re-asks it when a menu opens.
export async function wokenAddresses(candidates: WokenCandidate[]): Promise<Set<string>> {
  const marked = new Set<string>();
  for (const c of candidates) {
    try {
      if (await wasWoken(await scopeIdFor(c.x25519Public))) marked.add(c.address);
    } catch { /* a record we cannot read is not one we can mark */ }
  }
  return marked;
}

export function useWokenAccounts(accounts: DeviceAccount[] | null, enabled: boolean): Set<string> {
  const [woken, setWoken] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!enabled || !accounts) return;
    let cancelled = false;
    void (async () => {
      const candidates: WokenCandidate[] = [];
      for (const account of accounts) {
        if (!account.ks) continue; // a temporary session has no at-rest key to derive an id from
        try {
          candidates.push({ address: account.address, x25519Public: fromBase64(account.ks.x25519Public) });
        } catch { /* a malformed record is not the account we are looking for */ }
      }
      const marked = await wokenAddresses(candidates);
      if (!cancelled) setWoken(marked);
    })();
    return () => { cancelled = true; };
  }, [accounts, enabled]);

  return woken;
}
