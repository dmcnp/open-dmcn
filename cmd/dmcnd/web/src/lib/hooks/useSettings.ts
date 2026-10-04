import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { storeKey, useSyncChanges } from '../sync/useSync';
import { SettingsStore, emptySettings, type AppSettings } from '../api/settingsStore';
import { StorageConflictError } from '../api/personalStore';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';

// useSettings owns the synced account-level settings doc ("settings/app"). Writes
// use compare-and-swap with a re-read-and-retry loop so a concurrent edit on another
// device isn't clobbered.

interface SettingsContextValue {
  settings: AppSettings;
  // True once the account's own document has been read. Before then `settings` is the empty
  // default, which is indistinguishable from an account that never set anything, so a decision
  // that must not be undone a moment later (showing, then hiding, a rail row) waits for this.
  loaded: boolean;
  refreshSettings: () => void;
  updateSettings: (patch: Partial<Omit<AppSettings, 'v'>>) => Promise<void>;
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [settings, setSettings] = useState<AppSettings>(emptySettings());
  const [loaded, setLoaded] = useState(false);
  const storeRef = useRef<SettingsStore | null>(null);
  const syncRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;

    const store = new SettingsStore(keys);
    storeRef.current = store;

    let cancelled = false;
    const doSync = () => {
      store.get()
        .then(({ settings }) => { if (!cancelled) { setSettings(settings); setLoaded(true); } })
        .catch(() => { /* transient; keep last good */ });
    };
    syncRef.current = doSync;
    doSync();

    // Account settings change rarely and update optimistically on local edits, so we
    // don't poll on a timer — refresh only on tab focus / reconnect.
    const onWake = () => { if (document.visibilityState === 'visible' && navigator.onLine) doSync(); };
    document.addEventListener('visibilitychange', onWake);
    window.addEventListener('online', onWake);
    window.addEventListener('focus', onWake);

    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onWake);
      window.removeEventListener('online', onWake);
      window.removeEventListener('focus', onWake);
      storeRef.current = null;
      syncRef.current = () => {};
      setSettings(emptySettings());
      setLoaded(false);
    };
  }, [keys, sessionToken, isAuthenticated]);

  // A setting changed on another device shows up as soon as the change feed says so.
  useSyncChanges(storeKey('settings/app'), () => syncRef.current());

  const refreshSettings = useCallback(() => syncRef.current(), []);

  const updateSettings = useCallback(async (patch: Partial<Omit<AppSettings, 'v'>>) => {
    const store = storeRef.current;
    if (!store) return;
    for (let attempt = 0; attempt < 5; attempt++) {
      const { settings: cur, version } = await store.get();
      const next: AppSettings = { ...cur, ...patch, v: 1 };
      try {
        await store.put(next, version);
        setSettings(next);
        return;
      } catch (e) {
        if (e instanceof StorageConflictError) continue; // re-read + retry
        throw e;
      }
    }
    throw new Error('settings: too many concurrent edits, please retry');
  }, []);

  return createElement(
    SettingsContext.Provider,
    { value: { settings, loaded, refreshSettings, updateSettings } },
    children
  );
}

export function useSettings(): SettingsContextValue {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider');
  return ctx;
}
