import { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode, createElement } from 'react';
import type { IdentityKeyPair } from '../crypto/keys';
import {
  type WorkingKeys,
  importWorkingKeys,
  clearWorkingKeys,
  clearUnlockedHandles,
  gcWorkingHandles,
} from '../crypto/workingKeys';
import { migrateLegacyKeystore } from '../crypto/localKeystore';
import { loadUnlockedKeys, persistWorkingKeys } from '../accounts';
import { isStaySignedIn, workingKeyRef, getTabId, startPresence, liveTabIds } from '../sessionLifetime';
import { useAuth } from './useAuth';

interface KeysContextValue {
  keys: WorkingKeys | null;
  loading: boolean;
  // setKeys imports a freshly-decrypted raw key pair into non-extractable working
  // handles for `address`, persists them under this tab's session ref (so a refresh
  // doesn't re-prompt; a tab close orphans them for GC), and returns them so the caller
  // can sign the login challenge immediately. Temporary access reuses this — it just
  // skips writing the encrypted keystore, so no re-login material lands on disk.
  setKeys: (address: string, kp: IdentityKeyPair) => Promise<WorkingKeys>;
  // adoptKeys installs already-imported, already-persisted handles as this tab's
  // current account SYNCHRONOUSLY, so a caller can apply it and setSession() in one
  // continuation. The account switcher needs that: a render in which the new
  // account's key is paired with the outgoing account's session token would sign the
  // wrong mailbox's challenge.
  adoptKeys: (wk: WorkingKeys) => void;
  // clearKeys locks the current account (drops its working handles); the encrypted
  // keystore stays so the account can be unlocked again. Other accounts unlocked in
  // this tab are untouched — clearAllKeys locks every one of them.
  clearKeys: () => Promise<void>;
  clearAllKeys: () => Promise<void>;
}

const KeysContext = createContext<KeysContextValue | null>(null);

// Working handles are scoped to the tab's session via sessionLifetime.workingKeyRef:
// by default a per-tab id (sessionStorage) plus the address keys the handle, so
// closing the tab/browser orphans every account it held and re-unlock is required —
// a refresh keeps the same id and re-loads the handle with no prompt. "Stay signed
// in" instead keys by account alone, for persistence across restarts.
// Handles are non-extractable CryptoKeys — never raw bytes in web storage.
//
// This context tracks the ONE account the tab is currently acting as. Several may be
// unlocked at once (that's what makes the header's account switcher instant), but
// only the one adopted here can sign: a handle is loaded from its own account's ref
// and rejected unless it names that account, so relay challenges can't be signed with
// the wrong key; a missing/mismatched handle forces a clean re-unlock.
export function KeysProvider({ children }: { children: ReactNode }) {
  const [keys, setKeysState] = useState<WorkingKeys | null>(null);
  const [loading, setLoading] = useState(true);
  const { address } = useAuth();
  const gcDone = useRef(false);
  // Mirror of `keys` so the address effect can tell "already unlocked in memory"
  // (including a non-persisted temporary session) from "needs loading from disk".
  const keysRef = useRef<WorkingKeys | null>(null);
  const setBoth = useCallback((wk: WorkingKeys | null) => { keysRef.current = wk; setKeysState(wk); }, []);

  useEffect(() => {
    let cancelled = false;
    // An account switch adopts the handles before it changes the session, so this run
    // has nothing to load. Flipping to `loading` anyway would unmount the whole shell
    // (the protected route renders nothing while loading) for an IndexedDB round trip.
    if (!address || keysRef.current?.address !== address) setLoading(true);
    (async () => {
      await migrateLegacyKeystore();
      // One sweep per app load: drop closed-tab orphan handles (their tab id isn't in
      // the live set) and any persistent handles left over when stay-signed-in is off.
      // Include this tab's id so its own handle is never swept.
      if (!gcDone.current) {
        gcDone.current = true;
        const live = liveTabIds();
        live.add(getTabId());
        await gcWorkingHandles(isStaySignedIn(), live);
      }
      if (!address) {
        if (!cancelled) { setBoth(null); setLoading(false); }
        return;
      }
      // Already unlocked in memory for this account (a normal session just established,
      // or a temporary in-memory session) — keep those handles, don't reload/clobber.
      if (keysRef.current && keysRef.current.address === address) {
        if (!cancelled) setLoading(false);
        return;
      }
      // loadUnlockedKeys rejects a handle that isn't this account's, or that no
      // longer matches the keystore (stale after a re-import).
      const wk = await loadUnlockedKeys(address);
      if (!cancelled) { setBoth(wk); setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [address]);

  // Announce this tab is open (any tab, authenticated or not) so other tabs' GC keeps
  // its handle and reaps only genuine closed-tab orphans.
  useEffect(() => startPresence(), []);

  const adoptKeys = useCallback((wk: WorkingKeys) => {
    setBoth(wk);
    setLoading(false);
  }, [setBoth]);

  const setKeys = useCallback(async (addr: string, kp: IdentityKeyPair) => {
    const wk = await importWorkingKeys(addr, kp);
    await persistWorkingKeys(wk);
    adoptKeys(wk);
    return wk;
  }, [adoptKeys]);

  const clearKeys = useCallback(async () => {
    if (address) await clearWorkingKeys(workingKeyRef(address));
    setBoth(null);
  }, [address, setBoth]);

  const clearAllKeys = useCallback(async () => {
    await clearUnlockedHandles();
    setBoth(null);
  }, [setBoth]);

  return createElement(
    KeysContext.Provider,
    { value: { keys, loading, setKeys, adoptKeys, clearKeys, clearAllKeys } },
    children
  );
}

export function useKeys(): KeysContextValue {
  const ctx = useContext(KeysContext);
  if (!ctx) throw new Error('useKeys must be used within KeysProvider');
  return ctx;
}
