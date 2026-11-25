import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { FlagStore, type FlagRecord, type FlagDelta } from '../api/flagStore';
import { STORAGE_POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';
import { storeKey, useSyncChanges, useSyncLive } from '../sync/useSync';

// useFlags owns the extrinsic per-message metadata (read/unread, archived, starred,
// labels, deleted) from the "flags/" namespace of the personal store. Views (Inbox excludes
// archived, Archive shows archived, Starred, Deleted, unread counts) are filters over
// (messages) ∪ (these flags). Toggles apply a delta and write it back, optimistically
// updating the cache so the UI responds immediately; the next poll reconciles across
// devices (last-writer-wins per message).

interface FlagsContextValue {
  flags: Map<string, FlagRecord>;
  // ready is false until the first load settles. Until then every message reads as unarchived
  // and unread, so a view built on flags waits for it rather than drawing that and taking it back.
  ready: boolean;
  // synced is true once a list has actually come back. ready also turns true when the first load
  // FAILS, leaving an empty map; anything that treats "no flag record" as "never touched" (sender
  // rules filing new mail) waits for this instead, or it would overwrite every record it can't see.
  synced: boolean;
  refreshFlags: () => void;
  setFlag: (messageHash: string, delta: FlagDelta) => Promise<void>;
  // setFlagIfAbsent writes only if the store holds no record for the message yet, checked against
  // the store itself just before writing. For sender rules, which file "untouched" mail: a record
  // another device made since this tab last synced (the message read or starred on the phone) must
  // not be replaced by one holding only the folder. Resolves true when it wrote. A small window
  // remains between the read and the write; the store has no create-only write to close it.
  setFlagIfAbsent: (messageHash: string, delta: FlagDelta) => Promise<boolean>;
  markRead: (messageHash: string) => Promise<void>;
  isRead: (messageHash: string) => boolean;
  isArchived: (messageHash: string) => boolean;
  isStarred: (messageHash: string) => boolean;
  labelsOf: (messageHash: string) => string[];
  folderOf: (messageHash: string) => string | undefined;
  /** When the message was deleted (unix ms), or undefined while it is not in Deleted. */
  trashedAt: (messageHash: string) => number | undefined;
  isTrashed: (messageHash: string) => boolean;
  /** Move to Deleted. Nothing is removed; see lib/trash.ts. */
  trash: (messageHash: string) => Promise<void>;
  /** Take out of Deleted, back to wherever its other flags put it. */
  restore: (messageHash: string) => Promise<void>;
  addLabel: (messageHash: string, labelId: string) => Promise<void>;
  removeLabel: (messageHash: string, labelId: string) => Promise<void>;
  setFolder: (messageHash: string, folderId: string | undefined) => Promise<void>;
  removeFlags: (messageHash: string) => Promise<void>;
}

const FlagsContext = createContext<FlagsContextValue | null>(null);

export function FlagsProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [flags, setFlags] = useState<Map<string, FlagRecord>>(new Map());
  const [ready, setReady] = useState(false);
  const [synced, setSynced] = useState(false);
  const storeRef = useRef<FlagStore | null>(null);
  const flagsRef = useRef<Map<string, FlagRecord>>(new Map());
  const syncRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;

    const store = new FlagStore(keys);
    storeRef.current = store;

    let cancelled = false;
    const doSync = () => {
      store.list()
        .then(map => {
          if (cancelled) return;
          flagsRef.current = map;
          setFlags(map);
          setSynced(true);
        })
        .catch(() => { /* transient; keep the last good map */ })
        .finally(() => { if (!cancelled) setReady(true); });
    };
    syncRef.current = doSync;
    doSync();


    return () => {
      cancelled = true;
      storeRef.current = null;
      flagsRef.current = new Map();
      syncRef.current = () => {};
      setReady(false);
      setSynced(false);
      setFlags(new Map());
    };
  }, [keys, sessionToken, isAuthenticated]);

  // The timer stands down while the change feed answers; a change to flags/ refreshes instead.
  const live = useSyncLive();
  usePolling(() => { if (!live) syncRef.current(); }, STORAGE_POLL_INTERVAL_MS);
  useSyncChanges(storeKey('flags/'), () => syncRef.current());

  const refreshFlags = useCallback(() => syncRef.current(), []);

  const setFlag = useCallback(async (messageHash: string, delta: FlagDelta) => {
    if (!storeRef.current) return;
    const current = flagsRef.current.get(messageHash);
    const next = await storeRef.current.apply(messageHash, current, delta);
    // Optimistically update the cache so the UI reflects the change before the poll.
    const map = new Map(flagsRef.current);
    map.set(messageHash, next);
    flagsRef.current = map;
    setFlags(map);
  }, []);

  const setFlagIfAbsent = useCallback(async (messageHash: string, delta: FlagDelta) => {
    const store = storeRef.current;
    if (!store || flagsRef.current.has(messageHash)) return false;
    const existing = await store.get(messageHash);
    if (existing) {
      // Take the record in, so the message stops looking untouched here too.
      const map = new Map(flagsRef.current);
      map.set(messageHash, existing);
      flagsRef.current = map;
      setFlags(map);
      return false;
    }
    if (flagsRef.current.has(messageHash)) return false; // touched here meanwhile
    await setFlag(messageHash, delta);
    return true;
  }, [setFlag]);

  const markRead = useCallback(async (messageHash: string) => {
    const current = flagsRef.current.get(messageHash);
    if (current?.read) return; // already read — no write
    await setFlag(messageHash, { read: true });
  }, [setFlag]);

  const isRead = useCallback((h: string) => !!flags.get(h)?.read, [flags]);
  const isArchived = useCallback((h: string) => !!flags.get(h)?.archived, [flags]);
  const isStarred = useCallback((h: string) => !!flags.get(h)?.starred, [flags]);
  const labelsOf = useCallback((h: string) => flags.get(h)?.labelIds ?? [], [flags]);
  const folderOf = useCallback((h: string) => flags.get(h)?.folderId, [flags]);
  const trashedAt = useCallback((h: string) => flags.get(h)?.trashedAt, [flags]);
  const isTrashed = useCallback((h: string) => flags.get(h)?.trashedAt !== undefined, [flags]);
  const trash = useCallback((h: string) => setFlag(h, { trashedAt: Date.now() }), [setFlag]);
  const restore = useCallback((h: string) => setFlag(h, { trashedAt: undefined }), [setFlag]);

  const addLabel = useCallback(async (h: string, labelId: string) => {
    const cur = flagsRef.current.get(h)?.labelIds ?? [];
    if (cur.includes(labelId)) return;
    await setFlag(h, { labelIds: [...cur, labelId] });
  }, [setFlag]);
  const removeLabel = useCallback(async (h: string, labelId: string) => {
    const cur = flagsRef.current.get(h)?.labelIds ?? [];
    if (!cur.includes(labelId)) return;
    await setFlag(h, { labelIds: cur.filter(id => id !== labelId) });
  }, [setFlag]);
  const setFolder = useCallback((h: string, folderId: string | undefined) =>
    setFlag(h, { folderId }), [setFlag]);

  // removeFlags GCs a message's flag record when the message itself is deleted, so
  // orphaned "flags/<hash>" records don't accumulate in the personal store. Best-effort
  // and idempotent: a message with no flag record is a no-op, and a failed delete is
  // swallowed (the caller has already deleted the message — a stray flag record is
  // harmless, and the next delete attempt or a manual sweep can retry).
  const removeFlags = useCallback(async (messageHash: string) => {
    if (!storeRef.current) return;
    if (!flagsRef.current.has(messageHash)) return; // no record to reap
    try {
      await storeRef.current.remove(messageHash);
    } catch { /* harmless orphan; leave it */ }
    const map = new Map(flagsRef.current);
    map.delete(messageHash);
    flagsRef.current = map;
    setFlags(map);
  }, []);

  return createElement(
    FlagsContext.Provider,
    { value: { flags, ready, synced, refreshFlags, setFlag, setFlagIfAbsent, markRead, isRead, isArchived, isStarred, labelsOf, folderOf, trashedAt, isTrashed, trash, restore, addLabel, removeLabel, setFolder, removeFlags } },
    children
  );
}

export function useFlags(): FlagsContextValue {
  const ctx = useContext(FlagsContext);
  if (!ctx) throw new Error('useFlags must be used within FlagsProvider');
  return ctx;
}
