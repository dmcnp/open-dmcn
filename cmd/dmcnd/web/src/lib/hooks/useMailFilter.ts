import { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode, createElement } from 'react';
import { emptyFilterList, type FilterList, type MailFilter } from '../api/filterList';
import { deployment } from '../../deployment';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';

interface MailFilterContextValue {
  filter: FilterList | null;
  // ready is false until the first load resolves, so consumers don't act on a
  // not-yet-loaded (null) list.
  ready: boolean;
  blockSender: (senderAddress: string, senderKeyHex?: string) => Promise<void>;
}

const MailFilterContext = createContext<MailFilterContextValue | null>(null);

// MailFilterProvider loads the recipient's block/allow policy (the personal
// blocklist, §14.3) ONCE for the whole app and exposes it plus a key-bound block
// action. Sharing one instance (rather than a fresh per-consumer hook) is what keeps
// the reader from re-loading — and flickering — on every open.
export function MailFilterProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [filter, setFilter] = useState<FilterList | null>(null);
  const [ready, setReady] = useState(false);
  const clientRef = useRef<MailFilter | null>(null);

  // Gate on the account session, not just keys — same pairing race as
  // ContactsProvider: the blocklist must load against the real account token, not
  // the ephemeral pairing token that's live for a beat after keys are installed.
  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;
    const client = deployment.mailFilter(keys);
    clientRef.current = client;
    let cancelled = false;
    const load = () => client.get()
      .then(f => {
        if (cancelled) return;
        // Only replace on an actual change, so a wake-reload of an unchanged list
        // doesn't churn `filter` identity and re-render consumers. Compared against
        // the CURRENT filter rather than a remembered signature: this effect re-runs
        // on silent session renewal and its cleanup nulls `filter`, which a
        // remembered signature would outlive — swallowing the reload and leaving the
        // blocklist unloaded (blocked senders reading as merely pending).
        setFilter(prev => (JSON.stringify(prev) === JSON.stringify(f) ? prev : f));
      })
      .catch(() => { /* transient */ })
      .finally(() => { if (!cancelled) setReady(true); });
    load();
    // Refresh on wake so a block/allow edit made in Settings (a separate client)
    // reflects here without a full remount.
    const onWake = () => { if (document.visibilityState === 'visible' && navigator.onLine) load(); };
    document.addEventListener('visibilitychange', onWake);
    window.addEventListener('online', onWake);
    window.addEventListener('focus', onWake);
    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onWake);
      window.removeEventListener('online', onWake);
      window.removeEventListener('focus', onWake);
      clientRef.current = null;
      setReady(false);
      setFilter(null);
    };
  }, [keys, sessionToken, isAuthenticated]);

  // blockSender adds the sender's key to the unconditional key-bound blocklist
  // (§14.3.1) — so the block survives an address change. In deny mode we also list
  // the address for a human-readable entry; in allow mode we don't (adding to
  // `senders` there would ADMIT them). Re-reads the current list first so a stale
  // in-memory copy can't clobber concurrent edits.
  const blockSender = useCallback(async (senderAddress: string, senderKeyHex?: string) => {
    const client = clientRef.current;
    if (!client) return;
    const cur = (await client.get()) ?? emptyFilterList();
    const next: FilterList = {
      mode: cur.mode || 'deny',
      domains: [...(cur.domains ?? [])],
      senders: [...(cur.senders ?? [])],
      allow_verified: cur.allow_verified,
      sender_keys: [...(cur.sender_keys ?? [])],
    };
    if (senderKeyHex) {
      const k = senderKeyHex.toLowerCase();
      if (!next.sender_keys!.some(x => x.toLowerCase() === k)) next.sender_keys!.push(k);
    }
    if (next.mode === 'deny') {
      const a = senderAddress.trim().toLowerCase();
      if (!next.senders.some(x => x.trim().toLowerCase() === a)) next.senders.push(a);
    }
    await client.save(next);
    setFilter(next);
  }, []);

  const value: MailFilterContextValue = { filter, ready, blockSender };
  return createElement(MailFilterContext.Provider, { value }, children);
}

export function useMailFilter(): MailFilterContextValue {
  const ctx = useContext(MailFilterContext);
  if (!ctx) throw new Error('useMailFilter must be used within MailFilterProvider');
  return ctx;
}
