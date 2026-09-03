import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { MailboxSync, type Preview, type FullBody } from '../api/mailboxRest';
import { ApiError } from '../api/client';
import { POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';

export type { Preview } from '../api/mailboxRest';

// AccessState reflects the account's node-enforced access entitlement, learned from the
// mailbox-sync response: 'ok' (reads allowed), 'suspended' (lapsed/grace — reads locked,
// inbound still delivered), or 'closed' (terminal). The UI shows a banner for the latter two.
export type AccessState = 'ok' | 'suspended' | 'closed';

interface MessagesContextValue {
  messages: Preview[];
  error: string | null;
  accessState: AccessState;
  refresh: () => void;
  openMessage: (hash: string) => Promise<string>;
  openMessageFull: (hash: string) => Promise<FullBody>;
  deleteMessage: (hash: string) => Promise<void>;
}

const MessagesContext = createContext<MessagesContextValue | null>(null);

// MessagesProvider owns a single MailboxSync (REST) and polls the mailbox on a
// timer while the tab is visible and online. The relay still requires the client
// to sign each per-op challenge, so a poll is challenge → sign → complete. The
// inbox previews are decrypted/verified client-side; the private key never leaves
// the browser.
export function MessagesProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [messages, setMessages] = useState<Preview[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [accessState, setAccessState] = useState<AccessState>('ok');
  const clientRef = useRef<MailboxSync | null>(null);
  const syncRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;

    const client = new MailboxSync(keys, setMessages);
    clientRef.current = client;

    let cancelled = false;
    const doSync = () => {
      client.list()
        .then(() => { if (cancelled) return; setError(null); setAccessState('ok'); })
        .catch(err => {
          if (cancelled) return;
          // A node-enforced access lock is a 403 with a machine code — surface it as a
          // distinct account state (not a transient sync error) so the UI can explain it.
          if (err instanceof ApiError && err.status === 403 && err.code === 'access_suspended') {
            setAccessState('suspended');
            setError('Your account access is suspended — new mail is still delivered, but reading is locked until you reactivate.');
            return;
          }
          if (err instanceof ApiError && err.status === 403 && err.code === 'access_closed') {
            setAccessState('closed');
            setError('Your account has been closed.');
            return;
          }
          setError(err instanceof Error ? err.message : String(err));
        });
    };
    syncRef.current = doSync;

    doSync(); // initial sync


    return () => {
      cancelled = true;
      client.close();
      clientRef.current = null;
      syncRef.current = () => {};
      setMessages([]);
      setAccessState('ok');
    };
  }, [keys, sessionToken, isAuthenticated]);

  usePolling(() => syncRef.current(), POLL_INTERVAL_MS);

  const refresh = useCallback(() => syncRef.current(), []);

  const openMessage = useCallback((hash: string) => {
    if (!clientRef.current) return Promise.reject(new Error('mailbox not ready'));
    return clientRef.current.fetchBody(hash);
  }, []);

  const openMessageFull = useCallback((hash: string) => {
    if (!clientRef.current) return Promise.reject(new Error('mailbox not ready'));
    return clientRef.current.fetchFull(hash);
  }, []);

  const deleteMessage = useCallback((hash: string) => {
    if (!clientRef.current) return Promise.reject(new Error('mailbox not ready'));
    return clientRef.current.deleteMessage(hash);
  }, []);

  return createElement(
    MessagesContext.Provider,
    { value: { messages, error, accessState, refresh, openMessage, openMessageFull, deleteMessage } },
    children
  );
}

export function useMessages(): MessagesContextValue {
  const ctx = useContext(MessagesContext);
  if (!ctx) throw new Error('useMessages must be used within MessagesProvider');
  return ctx;
}
