import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import type { Preview, FullBody } from '../api/mailboxRest';
import { SentStore, SENT_HASH_PREFIX } from '../api/sentStore';
import { STORAGE_POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';

// The Sent folder reads self-sealed message envelopes from the owner-only personal store
// ("sent/" + "sent-body/" namespaces), not the mailbox. Each is a normal split envelope,
// so listing decrypts the small headers (the row previews) and opening decrypts the body
// (attachments + HTML) — the same path the inbox uses. See SentStore.

// Re-exported for callers that key rows / branch on Sent hashes.
export { SENT_HASH_PREFIX, isSentStoreHash } from '../api/sentStore';

interface SentContextValue {
  sent: Preview[];
  error: string | null;
  refreshSent: () => void;
  // Decrypt a Sent message's full body (attachments + HTML) on open.
  fetchSentFull: (hash: string) => Promise<FullBody>;
  deleteSent: (hash: string) => Promise<void>;
}

const SentContext = createContext<SentContextValue | null>(null);

// SentProvider owns a SentStore and polls the Sent headers on the same cadence as the
// mailbox, foreground/online-gated. Everything is decrypted client side (sealed to us
// alone); the private key never leaves the browser.
export function SentProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { address, sessionToken, isAuthenticated } = useAuth();
  const [sent, setSent] = useState<Preview[]>([]);
  const [error, setError] = useState<string | null>(null);
  const storeRef = useRef<SentStore | null>(null);
  const syncRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated || !address) return;

    const store = new SentStore(keys);
    storeRef.current = store;

    let cancelled = false;
    const doSync = () => {
      store.listPreviews()
        .then(previews => {
          if (cancelled) return;
          setSent(previews);
          setError(null);
        })
        .catch(err => { if (!cancelled) setError(err instanceof Error ? err.message : String(err)); });
    };
    syncRef.current = doSync;
    doSync();

    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible' && navigator.onLine) doSync();
    }, STORAGE_POLL_INTERVAL_MS);
    const onWake = () => { if (document.visibilityState === 'visible' && navigator.onLine) doSync(); };
    document.addEventListener('visibilitychange', onWake);
    window.addEventListener('online', onWake);
    window.addEventListener('focus', onWake);

    return () => {
      cancelled = true;
      clearInterval(id);
      document.removeEventListener('visibilitychange', onWake);
      window.removeEventListener('online', onWake);
      window.removeEventListener('focus', onWake);
      storeRef.current = null;
      syncRef.current = () => {};
      setSent([]);
    };
  }, [keys, sessionToken, isAuthenticated, address]);

  const refreshSent = useCallback(() => syncRef.current(), []);
  const fetchSentFull = useCallback((hash: string): Promise<FullBody> => {
    if (!storeRef.current) return Promise.reject(new Error('sent store not ready'));
    return storeRef.current.fetchFull(hash);
  }, []);
  const deleteSent = useCallback(async (hash: string) => {
    if (!storeRef.current) return;
    const messageId = hash.startsWith(SENT_HASH_PREFIX) ? hash.slice(SENT_HASH_PREFIX.length) : hash;
    await storeRef.current.delete(messageId);
    // Optimistically drop the row so it disappears before the next poll.
    setSent(prev => prev.filter(p => p.messageId !== messageId));
  }, []);

  return createElement(
    SentContext.Provider,
    { value: { sent, error, refreshSent, fetchSentFull, deleteSent } },
    children
  );
}

export function useSent(): SentContextValue {
  const ctx = useContext(SentContext);
  if (!ctx) throw new Error('useSent must be used within SentProvider');
  return ctx;
}
