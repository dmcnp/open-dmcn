import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { FlagStore, type FlagRecord, type FlagDelta } from '../api/flagStore';
import { STORAGE_POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';

// useFlags owns the extrinsic per-message metadata (read/unread, archived, starred,
// labels) from the "flags/" namespace of the personal store. Views (Inbox excludes
// archived, Archive shows archived, Starred, unread counts) are filters over
// (messages) ∪ (these flags). Toggles apply a delta and write it back, optimistically
// updating the cache so the UI responds immediately; the next poll reconciles across
// devices (last-writer-wins per message).

interface FlagsContextValue {
  flags: Map<string, FlagRecord>;
  refreshFlags: () => void;
  setFlag: (messageHash: string, delta: FlagDelta) => Promise<void>;
  markRead: (messageHash: string) => Promise<void>;
  isRead: (messageHash: string) => boolean;
  isArchived: (messageHash: string) => boolean;
  isStarred: (messageHash: string) => boolean;
  labelsOf: (messageHash: string) => string[];
  folderOf: (messageHash: string) => string | undefined;
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
        })
        .catch(() => { /* transient; keep the last good map */ });
    };
    syncRef.current = doSync;
    doSync();


    return () => {
      cancelled = true;
      storeRef.current = null;
      flagsRef.current = new Map();
      syncRef.current = () => {};
      setFlags(new Map());
    };
  }, [keys, sessionToken, isAuthenticated]);

  usePolling(() => syncRef.current(), STORAGE_POLL_INTERVAL_MS);

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
    { value: { flags, refreshFlags, setFlag, markRead, isRead, isArchived, isStarred, labelsOf, folderOf, addLabel, removeLabel, setFolder, removeFlags } },
    children
  );
}

export function useFlags(): FlagsContextValue {
  const ctx = useContext(FlagsContext);
  if (!ctx) throw new Error('useFlags must be used within FlagsProvider');
  return ctx;
}
