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

export function useWokenAccounts(accounts: DeviceAccount[] | null, enabled: boolean): Set<string> {
  const [woken, setWoken] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!enabled || !accounts) return;
    let cancelled = false;
    void (async () => {
      const marked = new Set<string>();
      for (const account of accounts) {
        if (!account.ks) continue; // a temporary session has no at-rest key to derive an id from
        try {
          if (await wasWoken(await scopeIdFor(fromBase64(account.ks.x25519Public)))) marked.add(account.address);
        } catch { /* a record we cannot read is not one we can mark */ }
      }
      if (!cancelled) setWoken(marked);
    })();
    return () => { cancelled = true; };
  }, [accounts, enabled]);

  return woken;
}
