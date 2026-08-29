import { useCallback, useEffect, useRef, useState } from 'react';
import type { DeviceAccount } from '../accounts';
import { loadUnlockedKeys } from '../accounts';
import { fetchAccountUnread, forgetAccountUnread } from '../api/accountUnread';
import { BACKGROUND_UNREAD_INTERVAL_MS } from '../config';

// Unread counts for the accounts this tab holds unlocked but isn't currently acting
// as — what puts a dot on the account switcher when mail lands somewhere else.
//
// Deliberately much slower than the inbox poll: this is an ambient "there's
// something over there" signal, not a live mailbox. Accounts are polled one at a
// time (a burst of parallel mailbox reads would be a poor trade for a badge), only
// while the tab is visible and online, and every failure is silent — a background
// account that can't be read simply has no count.

export function useBackgroundUnread(accounts: DeviceAccount[] | null, activeAddress: string | null) {
  const [counts, setCounts] = useState<Map<string, number>>(new Map());
  const inFlight = useRef(false);
  // A refresh asked for while one is running (an account just unlocked, or the tab
  // switched): finish the pass, then immediately do another. Dropping it instead
  // would leave the new account uncounted until the next tick, a minute away.
  const rerun = useRef(false);
  // Latest inputs, so the interval callback never closes over a stale account list.
  const accountsRef = useRef(accounts);
  accountsRef.current = accounts;
  const activeRef = useRef(activeAddress);
  activeRef.current = activeAddress;

  const runOnce = useCallback(async () => {
    const targets = (accountsRef.current ?? []).filter(a => a.unlocked && a.address !== activeRef.current);
    // Whatever we're no longer tracking (locked, removed, or now the active account)
    // must not leave a stale count behind.
    setCounts(prev => {
      const keep = new Set(targets.map(a => a.address));
      if ([...prev.keys()].every(k => keep.has(k))) return prev;
      const next = new Map<string, number>();
      for (const [k, v] of prev) if (keep.has(k)) next.set(k, v);
      return next;
    });
    for (const account of targets) {
      try {
        const wk = await loadUnlockedKeys(account.address, account.ks);
        if (!wk) { forgetAccountUnread(account.address); continue; }
        const n = await fetchAccountUnread(account.address, wk);
        setCounts(prev => (prev.get(account.address) === n ? prev : new Map(prev).set(account.address, n)));
      } catch {
        // Offline, an expired session we couldn't re-mint, a suspended account:
        // leave whatever we last knew and try again next tick.
      }
    }
  }, []);

  const refresh = useCallback(async () => {
    if (inFlight.current) { rerun.current = true; return; }
    inFlight.current = true;
    try {
      do {
        rerun.current = false;
        await runOnce();
      } while (rerun.current);
    } finally {
      inFlight.current = false;
    }
  }, [runOnce]);

  // The active account owns its own (live) badge, and its cached background session
  // is dead weight once the real sync takes over.
  useEffect(() => {
    if (activeAddress) forgetAccountUnread(activeAddress);
  }, [activeAddress]);

  // Count as soon as the set of eligible accounts changes — the account list arrives
  // asynchronously after mount, and unlocking or switching changes it again. Keyed on
  // the addresses rather than the array so a same-set refresh doesn't re-poll.
  const targetSig = (accounts ?? [])
    .filter(a => a.unlocked && a.address !== activeAddress)
    .map(a => a.address)
    .sort()
    .join('|');
  useEffect(() => { void refresh(); }, [targetSig, refresh]);

  useEffect(() => {
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible' && navigator.onLine) void refresh();
    }, BACKGROUND_UNREAD_INTERVAL_MS);
    const onWake = () => { if (document.visibilityState === 'visible' && navigator.onLine) void refresh(); };
    document.addEventListener('visibilitychange', onWake);
    window.addEventListener('online', onWake);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', onWake);
      window.removeEventListener('online', onWake);
    };
  }, [refresh]);

  const total = [...counts.values()].reduce((a, b) => a + b, 0);
  return { counts, total, refresh };
}
