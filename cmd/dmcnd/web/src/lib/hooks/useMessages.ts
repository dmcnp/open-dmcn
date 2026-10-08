import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { MailboxSync, type Preview, type FullBody } from '../api/mailboxRest';
import { ApiError } from '../api/client';
import { isUnapprovedDevice } from '../api/deviceRegistry';
import { POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';
import { deployment } from '@deployment';
import { storageKey } from '../appContext';
import { useSyncBus } from '../sync/useSync';
import { feedPass } from '../sync/feedSync';
import { ChangeFeedUnavailable } from '../sync/changes';

export type { Preview } from '../api/mailboxRest';

// AccessState reflects the account's node-enforced access entitlement, learned from the
// mailbox-sync response: 'ok' (reads allowed), 'suspended' (reads locked, inbound still
// delivered), or 'closed' (terminal). The UI shows a banner for the latter two. A current relay
// never reports 'suspended': grace leaves reads open (so the owner can export) and locks only
// sending, so it is reported by a relay from before that change alone. Grace itself is not
// visible here; a deployment that needs to say so reads it from its own account service.
// 'unapproved-device' is this BROWSER rather than the account: the account has enrolled devices
// and this is not one of them (never paired, or removed from another device), so the way back
// is pairing it, which the inbox offers.
export type AccessState = 'ok' | 'suspended' | 'closed' | 'unapproved-device';

interface MessagesContextValue {
  messages: Preview[];
  // True once a full listing has landed for this account. Until then `messages` being empty says
  // nothing about the mailbox, which matters to anything that would act on a message's absence.
  loaded: boolean;
  error: string | null;
  accessState: AccessState;
  // Resolves when the sync it started has settled, so a caller that shows progress
  // (the pull-to-refresh indicator) can keep it up for exactly that long.
  refresh: () => Promise<void>;
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
  const { publish, setLive } = useSyncBus();
  const [messages, setMessages] = useState<Preview[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accessState, setAccessState] = useState<AccessState>('ok');
  const clientRef = useRef<MailboxSync | null>(null);
  const syncRef = useRef<() => Promise<void>>(() => Promise.resolve());

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;

    const client = new MailboxSync(keys, setMessages, undefined, deployment.identities ? () => deployment.identities!(keys) : undefined);
    clientRef.current = client;

    let cancelled = false;
    const synced = () => { if (cancelled) return; setLoaded(true); setError(null); setAccessState('ok'); };
    const failed = (err: unknown) => {
          if (cancelled) return;
          // A node-enforced access lock is a 403 with a machine code — surface it as a
          // distinct account state (not a transient sync error) so the UI can explain it.
          // A current relay locks only a closed mailbox (a suspended account can still read and
          // export its mail); access_suspended comes from a relay that predates that, and is
          // kept for as long as relays of both ages may answer (grace-open shim: remove once every relay runs grace-open; TODO P3).
          if (err instanceof ApiError && err.status === 403 && err.code === 'access_suspended') {
            setAccessState('suspended');
            setError('Reading is paused on this account. New mail is still being delivered, and you can read it again once access is restored.');
            return;
          }
          if (err instanceof ApiError && err.status === 403 && err.code === 'access_closed') {
            setAccessState('closed');
            setError('Your account has been closed.');
            return;
          }
          if (isUnapprovedDevice(err)) {
            setAccessState('unapproved-device');
            setError('This browser is not one of the approved devices for this account, so it cannot open the mailbox.');
            return;
          }
          setError(err instanceof Error ? err.message : String(err));
    };
    const listOnce = () => client.list().then(synced, failed);

    // Where the deployment's relays keep a change log, a poll asks what changed rather than
    // re-listing, and the kept rows are drawn at once while it does (sync/feedSync.ts). A relay
    // that turns out to keep none drops this session back to listing, as before.
    const feed = deployment.changeFeed ? deployment.changeFeed(keys) : null;
    let useFeed = feed !== null;
    const feedOnce = (): Promise<void> =>
      feedPass(feed!, client, publish)
        .then(() => { if (!cancelled) setLive(true); synced(); })
        .catch(err => {
          if (err instanceof ChangeFeedUnavailable) {
            useFeed = false;
            if (!cancelled) setLive(false);
            return listOnce();
          }
          failed(err);
        });
    // One pass at a time: a poll, a push wake-up and a pull-to-refresh can all ask at once.
    let inFlight: Promise<void> | null = null;
    const doSync = () => (inFlight ??= (useFeed ? feedOnce() : listOnce()).finally(() => { inFlight = null; }));
    syncRef.current = doSync;

    if (useFeed) void client.showKept();
    doSync(); // initial sync

    // One tab per account keeps the list on this device (see MailboxSync.becomeWriter): whichever
    // holds this lock. The others read the kept list at start and otherwise keep theirs in memory.
    // A browser without Web Locks has one tab's worth of guarantee, which is every tab writing.
    let releaseLock: (() => void) | null = null;
    const takeOver = () => { void client.becomeWriter().catch(err => console.warn('list cache: could not take over', err)); };
    if (typeof navigator !== 'undefined' && navigator.locks) {
      void navigator.locks.request(storageKey(`dmcn-list:${keys.address.toLowerCase()}`), () =>
        new Promise<void>(release => {
          releaseLock = release;
          if (cancelled) release(); else takeOver();
        }),
      ).catch(() => undefined);
    } else {
      takeOver();
    }


    return () => {
      cancelled = true;
      // Let go only once this instance's writes have landed, so the next writer starts from them.
      void client.settled().finally(() => releaseLock?.());
      client.close();
      clientRef.current = null;
      syncRef.current = () => Promise.resolve();
      setMessages([]);
      setLoaded(false);
      setAccessState('ok');
      setLive(false);
    };
  }, [keys, sessionToken, isAuthenticated, publish, setLive]);

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
    { value: { messages, loaded, error, accessState, refresh, openMessage, openMessageFull, deleteMessage } },
    children
  );
}

export function useMessages(): MessagesContextValue {
  const ctx = useContext(MessagesContext);
  if (!ctx) throw new Error('useMessages must be used within MessagesProvider');
  return ctx;
}
