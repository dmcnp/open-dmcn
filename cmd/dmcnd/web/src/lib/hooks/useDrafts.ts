import { createContext, createElement, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { DraftStore, type DraftSummary } from '../api/draftStore';
import { loadLocalKeystore } from '../crypto/localKeystore';
import { STORAGE_POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';
import { storeKey, useSyncChanges, useSyncLive } from '../sync/useSync';

// The Drafts folder: the messages this account has started and not sent, from the owner-only
// personal store (see DraftStore), refreshed on the same terms as Sent — the change feed when the
// relay keeps one, the storage poll when it does not. Each refresh also uploads what this device
// kept and no open composer is going to save (DraftStore.settleLocal).

interface DraftsContextValue {
  drafts: DraftSummary[];
  /** True once the drafts have been listed for this account, so an empty list means none. */
  loaded: boolean;
  /** The account's store; null until keys and the session are in. */
  store: DraftStore | null;
  refreshDrafts: () => Promise<void>;
  /** A composer in this tab has a draft open (or no longer does); a refresh leaves its device copy to it. */
  setOpen: (id: string, open: boolean) => void;
}

const DraftsContext = createContext<DraftsContextValue | null>(null);

export function DraftsProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { address, sessionToken, isAuthenticated } = useAuth();
  const [drafts, setDrafts] = useState<DraftSummary[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [store, setStore] = useState<DraftStore | null>(null);
  const syncRef = useRef<() => Promise<void>>(() => Promise.resolve());
  const openIds = useRef(new Set<string>());

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated || !address) return;
    let cancelled = false;
    void (async () => {
      // A temporary session keeps nothing of the account on this computer, drafts included. Told
      // apart the way the shell tells it: it has no keystore here.
      const keepLocal = (await loadLocalKeystore(address).catch(() => null)) !== null;
      if (cancelled) return;
      const s = new DraftStore(keys, { keepLocal });
      const doSync = async () => {
        try {
          await s.settleLocal(openIds.current);
        } catch { /* the device copies stay for the next pass */ }
        try {
          const list = await s.list();
          if (cancelled) return;
          setDrafts(list);
          setLoaded(true);
        } catch (err) {
          console.warn('Drafts: could not list', err);
        }
      };
      syncRef.current = doSync;
      setStore(s);
      void doSync();
    })();
    return () => {
      cancelled = true;
      syncRef.current = () => Promise.resolve();
      setStore(null);
      setDrafts([]);
      setLoaded(false);
    };
  }, [keys, sessionToken, isAuthenticated, address]);

  const live = useSyncLive();
  usePolling(() => { if (!live) void syncRef.current(); }, STORAGE_POLL_INTERVAL_MS);
  useSyncChanges(storeKey('drafts/'), () => { void syncRef.current(); });

  const refreshDrafts = useCallback(() => syncRef.current(), []);
  const setOpen = useCallback((id: string, open: boolean) => {
    if (open) openIds.current.add(id);
    else openIds.current.delete(id);
  }, []);

  return createElement(
    DraftsContext.Provider,
    { value: { drafts, loaded, store, refreshDrafts, setOpen } },
    children,
  );
}

export function useDrafts(): DraftsContextValue {
  const ctx = useContext(DraftsContext);
  if (!ctx) throw new Error('useDrafts must be used within DraftsProvider');
  return ctx;
}
