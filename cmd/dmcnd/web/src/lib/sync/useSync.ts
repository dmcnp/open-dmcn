import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { ChangeEvent } from './changes';
import type { ChangeBatch } from './feedSync';

// The change feed's bus. MessagesProvider drives the feed (the mail list and the feed position
// live together, see feedSync.ts) and publishes each batch here; every other keeper of relay
// state — Sent, flags, contacts, labels, settings, the mail filter — listens for the changes
// that touch it and refreshes then, instead of on a timer.
//
// `live` says the feed is answering. While it is, the timers that re-list personal storage stand
// down; when it is not (a deployment or relay without a change log), everything polls as before.

type Listener = (b: ChangeBatch) => void;

interface SyncContextValue {
  live: boolean;
  setLive: (live: boolean) => void;
  publish: (b: ChangeBatch) => void;
  subscribe: (fn: Listener) => () => void;
}

const NO_SYNC: SyncContextValue = { live: false, setLive: () => {}, publish: () => {}, subscribe: () => () => {} };

const SyncContext = createContext<SyncContextValue | null>(null);

export function SyncProvider({ children }: { children: ReactNode }) {
  const [live, setLive] = useState(false);
  const listeners = useRef(new Set<Listener>());
  const publish = useCallback((b: ChangeBatch) => {
    for (const fn of listeners.current) {
      try { fn(b); } catch (err) { console.warn('change feed listener failed', err); }
    }
  }, []);
  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => { listeners.current.delete(fn); };
  }, []);
  const value = useMemo(() => ({ live, setLive, publish, subscribe }), [live, publish, subscribe]);
  return createElement(SyncContext.Provider, { value }, children);
}

export function useSyncBus(): SyncContextValue {
  return useContext(SyncContext) ?? NO_SYNC;
}

/** Whether the change feed is answering, so a timer can stand down. */
export function useSyncLive(): boolean {
  return useSyncBus().live;
}

/** Matches a personal-store key: exactly, or everything under it when it ends in '/'. */
export function storeKey(keyOrPrefix: string): (e: ChangeEvent) => boolean {
  return e =>
    (e.kind === 'kv_put' || e.kind === 'kv_deleted') && !!e.key &&
    (keyOrPrefix.endsWith('/') ? e.key.startsWith(keyOrPrefix) : e.key === keyOrPrefix);
}

export const filterChanged = (e: ChangeEvent): boolean => e.kind === 'filter_changed';

/**
 * Call onChange once for each published batch with an event `match` accepts — and for every
 * resync, after which anything may have changed.
 */
export function useSyncChanges(match: (e: ChangeEvent) => boolean, onChange: () => void): void {
  const { subscribe } = useSyncBus();
  const matchRef = useRef(match);
  matchRef.current = match;
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  useEffect(() => subscribe(b => {
    if (b.resync || b.events.some(e => matchRef.current(e))) onChangeRef.current();
  }), [subscribe]);
}
