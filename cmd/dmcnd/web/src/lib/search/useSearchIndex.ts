import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { FullBody } from '../api/mailboxRest';
import { useKeys } from '../hooks/useKeys';
import { useAuth } from '../hooks/useAuth';
import { useMessages } from '../hooks/useMessages';
import { useSent, isSentStoreHash } from '../hooks/useSent';
import { useContacts } from '../hooks/useContacts';
import { useMailFilter } from '../hooks/useMailFilter';
import { categorizeSender } from '../trust/category';
import { storageKey } from '../appContext';
import { userAttachments } from '../userAttachments';
import { deployment } from '@deployment';
import { SearchIndex, deriveSearchKey } from './indexStore';
import { Backfiller, type Candidate } from './backfill';
import { globToRegExp, type Hits, type ParsedQuery } from './query';

// SearchIndexProvider keeps the current account's on-device search index (indexStore.ts) level
// with its mailbox and Sent folder, and answers the inbox's lookups against it.
//
// It lives and dies with the unlocked account, like every provider here: the index opens when the
// keys arrive and is dropped from memory when they go, which is what "encrypted at rest, readable
// only while unlocked" comes to in practice. What was written stays written, so the next unlock
// picks up where this one stopped.
//
// Several tabs of one account share one IndexedDB copy, so only one of them writes: whichever
// holds the Web Lock for it. The others only read, and re-read when the writer says (over a
// BroadcastChannel) that it has written something. Browsers without either API have one writer
// per tab, which is safe for a single tab and merely wasteful for several.

export interface SearchProgress {
  /** Messages searchable by their text. */
  indexed: number;
  /** Messages that will be, once the index has caught up. */
  total: number;
}

interface SearchContextValue {
  /** null while there is no index (locked, starting, or a handle too old to derive a key from). */
  progress: SearchProgress | null;
  /** Bumps whenever the index changes, so a lookup worth repeating can be. */
  version: number;
  lookup: (q: ParsedQuery) => Promise<Hits>;
  /** Index a message the reader has just opened, without fetching it again. */
  noteBody: (hash: string, full: FullBody) => void;
  /** Throw this device's index away and build it again. */
  clear: () => Promise<void>;
}

const EMPTY_HITS = (): Hits => ({ words: new Map(), files: new Map() });
const NO_SEARCH: SearchContextValue = {
  progress: null,
  version: 0,
  lookup: async () => EMPTY_HITS(),
  noteBody: () => {},
  clear: async () => {},
};

const SearchContext = createContext<SearchContextValue | null>(null);

const namesOf = (full: FullBody) => userAttachments(full.attachments).map(a => a.filename);

const PROGRESS_THROTTLE_MS = 500;
const NOTE_FLUSH_MS = 2000;

export function SearchIndexProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { address, isAuthenticated } = useAuth();
  const { messages, loaded: messagesLoaded, accessState, openMessageFull } = useMessages();
  const { sent, loaded: sentLoaded, fetchSentFull } = useSent();
  const { contactByAddress, ready: contactsReady } = useContacts();
  const { filter: mailFilter, ready: filterReady } = useMailFilter();

  const [index, setIndex] = useState<SearchIndex | null>(null);
  const [writer, setWriter] = useState<Backfiller | null>(null);
  const [progress, setProgress] = useState<SearchProgress | null>(null);
  const [version, setVersion] = useState(0);

  // What the backfill may index: every message that is mail (not a control message) and not from
  // a blocked sender. Held in a ref so the long-lived callbacks below read the current list.
  const candidatesRef = useRef<Candidate[]>([]);
  const allowedRef = useRef<Set<string>>(new Set());
  const accessRef = useRef(accessState);
  accessRef.current = accessState;
  const fetchRef = useRef<(hash: string) => Promise<FullBody>>(() => Promise.reject(new Error('not ready')));
  fetchRef.current = (hash: string) => (isSentStoreHash(hash) ? fetchSentFull(hash) : openMessageFull(hash));

  const recount = useCallback((idx: SearchIndex | null) => {
    if (!idx) { setProgress(null); return; }
    let indexed = 0;
    let total = 0;
    for (const c of candidatesRef.current) {
      if (c.blocked) continue;
      total++;
      if (idx.has(c.hash)) indexed++;
    }
    setProgress(p => (p && p.indexed === indexed && p.total === total ? p : { indexed, total }));
  }, []);

  // Open the index, and take the writer's lock for it, for as long as this account is unlocked.
  // Not keyed on the session token: the index never talks to the server (the fetches go through
  // the mailbox and Sent providers, which follow the token themselves), and reopening it on every
  // renewal would stop and restart a backfill for nothing.
  useEffect(() => {
    const root = keys?.aliasRoot;
    if (!keys || !root || !address || !isAuthenticated) return;
    let cancelled = false;
    let idx: SearchIndex | null = null;
    let backfill: Backfiller | null = null;
    let releaseLock: (() => void) | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let progressTimer: ReturnType<typeof setTimeout> | undefined;
    const channelName = storageKey('dmcn-search');
    const channel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel(channelName) : null;
    const me = address.toLowerCase();

    const runnable = () =>
      document.visibilityState === 'visible' && navigator.onLine && accessRef.current === 'ok';
    const kick = () => backfill?.kick();
    const flushNow = () => { void idx?.flush().catch(() => undefined); };

    const becomeWriter = async () => {
      if (cancelled || !idx) return;
      const opened = idx;
      // Whatever this tab read before it held the lock may be older than what the last writer
      // flushed on its way out (it flushes before it lets go). Writing from a stale manifest would
      // hand out document numbers that tab already used, so start again from what is on disk.
      await opened.reload();
      if (cancelled) return;
      recount(opened);
      backfill = new Backfiller({
        index: opened,
        fetch: hash => fetchRef.current(hash).then(full => ({ text: full.bodyText, filenames: namesOf(full) })),
        runnable,
        onProgress: flushed => {
          if (flushed) {
            setVersion(v => v + 1);
            channel?.postMessage({ address: me });
          }
          if (progressTimer === undefined) {
            progressTimer = setTimeout(() => { progressTimer = undefined; recount(opened); }, PROGRESS_THROTTLE_MS);
          }
        },
        retryLater: ms => { clearTimeout(retryTimer); retryTimer = setTimeout(kick, ms); },
      });
      setWriter(backfill);
    };

    (async () => {
      try {
        const opened = await SearchIndex.open(address, await deriveSearchKey(root, address));
        if (cancelled) return;
        idx = opened;
        setIndex(opened);
        recount(opened);
      } catch (err) {
        console.warn('search index unavailable on this device', err);
        return;
      }
      if (typeof navigator !== 'undefined' && navigator.locks) {
        void navigator.locks.request(storageKey(`dmcn-search:${me}`), () =>
          new Promise<void>(release => {
            releaseLock = release;
            if (cancelled) release(); else void becomeWriter();
          }),
        ).catch(() => undefined);
      } else {
        void becomeWriter();
      }
    })();

    if (channel) {
      channel.onmessage = e => {
        if (backfill || !idx || (e.data as { address?: string })?.address !== me) return;
        const opened = idx;
        void opened.reload().then(() => { if (!cancelled) { recount(opened); setVersion(v => v + 1); } });
      };
    }
    document.addEventListener('visibilitychange', kick);
    window.addEventListener('online', kick);
    window.addEventListener('pagehide', flushNow);

    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', kick);
      window.removeEventListener('online', kick);
      window.removeEventListener('pagehide', flushNow);
      clearTimeout(retryTimer);
      clearTimeout(progressTimer);
      channel?.close();
      const stopping = backfill?.stop() ?? Promise.resolve();
      void stopping.finally(() => releaseLock?.());
      setWriter(null);
      setIndex(null);
      setProgress(null);
    };
  }, [keys, address, isAuthenticated, recount]);

  // Keep the candidate list current and hand it to the writer. Nothing is decided until contacts
  // and the block list have loaded: before that, a blocked sender is indistinguishable from any
  // other, and indexing their mail only to remove it a moment later is the wrong way round.
  useEffect(() => {
    if (!contactsReady || !filterReady || !address) return;
    const control = new Set(deployment.controlSubjects);
    const me = address.toLowerCase();
    const blocked = (sender: string, key: string) =>
      sender.toLowerCase() !== me && categorizeSender(sender, key, contactByAddress(sender), mailFilter) === 'blocked';
    const list: Candidate[] = [];
    for (const m of messages) {
      if (control.has(m.subject)) continue;
      list.push({ hash: m.hash, sentAt: m.sentAt, blocked: blocked(m.senderAddress, m.senderPublicKey) });
    }
    for (const p of sent) list.push({ hash: p.hash, sentAt: p.sentAt, blocked: false });
    candidatesRef.current = list;
    allowedRef.current = new Set(list.filter(c => !c.blocked).map(c => c.hash));
    writer?.update(list, messagesLoaded && sentLoaded);
    recount(index);
  }, [messages, sent, messagesLoaded, sentLoaded, contactsReady, filterReady, contactByAddress, mailFilter, address, writer, index, recount]);

  // A new access state can make fetching possible again (a reactivated account).
  useEffect(() => { if (accessState === 'ok') writer?.kick(); }, [accessState, writer]);

  const noteTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const noteBody = useCallback((hash: string, full: FullBody) => {
    if (!index || !writer || index.has(hash) || !allowedRef.current.has(hash)) return;
    void index.add(hash, full.bodyText, namesOf(full)).then(() => {
      recount(index);
      clearTimeout(noteTimer.current);
      noteTimer.current = setTimeout(() => {
        void index.flush().then(() => setVersion(v => v + 1)).catch(() => undefined);
      }, NOTE_FLUSH_MS);
    }).catch(err => console.warn('search index: could not index an opened message', err));
  }, [index, writer, recount]);
  useEffect(() => () => clearTimeout(noteTimer.current), []);

  const lookup = useCallback(async (q: ParsedQuery): Promise<Hits> => {
    const hits = EMPTY_HITS();
    if (!index) return hits;
    // A record that will not open (storage damaged, or tampered with) costs that one term its body
    // matches, never the search: the header part still answers.
    const safe = async (f: () => Promise<Set<string>>) => {
      try { return await f(); } catch (err) { console.warn('search index: lookup failed', err); return new Set<string>(); }
    };
    for (const w of q.words) {
      const [body, names] = await Promise.all([safe(() => index.wordHits(w)), safe(() => index.filenameHits(w, null))]);
      for (const h of names) body.add(h);
      hits.words.set(w, body);
    }
    for (const f of q.filenames) hits.files.set(f, await safe(() => index.filenameHits(f, globToRegExp(f))));
    return hits;
  }, [index]);

  const clear = useCallback(async () => {
    if (!index) return;
    await index.clear();
    recount(index);
    setVersion(v => v + 1);
    writer?.kick();
  }, [index, writer, recount]);

  const value = useMemo<SearchContextValue>(
    () => ({ progress, version, lookup, noteBody, clear }),
    [progress, version, lookup, noteBody, clear],
  );
  return createElement(SearchContext.Provider, { value }, children);
}

/** The search index for the current account; a no-op outside SearchIndexProvider. */
export function useSearch(): SearchContextValue {
  return useContext(SearchContext) ?? NO_SEARCH;
}

const LOOKUP_DEBOUNCE_MS = 150;

/**
 * What the index says about a parsed query's words and filename patterns, or null while there is
 * nothing to ask. Re-asked whenever the index changes, so results fill in as it catches up.
 */
export function useSearchHits(q: ParsedQuery): Hits | null {
  const { lookup, version } = useSearch();
  const [hits, setHits] = useState<Hits | null>(null);
  const key = JSON.stringify([q.words, q.filenames]);
  const qRef = useRef(q);
  qRef.current = q;
  useEffect(() => {
    if (q.words.length === 0 && q.filenames.length === 0) { setHits(null); return; }
    let cancelled = false;
    const t = setTimeout(() => {
      void lookup(qRef.current).then(h => { if (!cancelled) setHits(h); });
    }, LOOKUP_DEBOUNCE_MS);
    return () => { cancelled = true; clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `key` is q's words and filenames
  }, [key, version, lookup]);
  return hits;
}
