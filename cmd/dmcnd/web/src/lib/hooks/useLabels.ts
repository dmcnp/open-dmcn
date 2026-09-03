import { createContext, useContext, useState, useEffect, useRef, useCallback, ReactNode, createElement } from 'react';
import { LabelStore, emptyLabelsDoc, type LabelsDoc, type LabelDef, type FolderDef } from '../api/labelStore';
import { StorageConflictError } from '../api/personalStore';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { randomHex } from '../crypto/bytes';

// useLabels owns the label + folder DEFINITIONS (names/colors) from
// "settings/labels". Definitions are a low-churn singleton, so writes use
// compare-and-swap with a re-read-and-retry loop (the provider caches the latest
// version). Per-message assignment stays in the flag records (useFlags); a labelId /
// folderId with no matching definition here is simply ignored by the views, so
// deleting a definition cleanly removes it everywhere with no flag cleanup.

// A short random id for a new label/folder.
function newId(): string {
  return randomHex(8);
}

// Default palette offered when creating a label.
export const LABEL_COLORS = ['#ef4444', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ec4899', '#64748b'];

interface LabelsContextValue {
  labels: LabelDef[];
  folders: FolderDef[];
  knownFolderIds: Set<string>;
  labelById: (id: string) => LabelDef | undefined;
  folderById: (id: string) => FolderDef | undefined;
  refreshLabels: () => void;
  createLabel: (name: string, color: string) => Promise<void>;
  renameLabel: (id: string, name: string, color?: string) => Promise<void>;
  deleteLabel: (id: string) => Promise<void>;
  createFolder: (name: string) => Promise<void>;
  renameFolder: (id: string, name: string) => Promise<void>;
  deleteFolder: (id: string) => Promise<void>;
}

const LabelsContext = createContext<LabelsContextValue | null>(null);

export function LabelsProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [doc, setDoc] = useState<LabelsDoc>(emptyLabelsDoc());
  const storeRef = useRef<LabelStore | null>(null);
  const syncRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;

    const store = new LabelStore(keys);
    storeRef.current = store;

    let cancelled = false;
    const doSync = () => {
      store.get()
        .then(({ doc }) => { if (!cancelled) setDoc(doc); })
        .catch(() => { /* transient; keep the last good doc */ });
    };
    syncRef.current = doSync;
    doSync();

    // Definitions change rarely and are updated optimistically on local edits, so we
    // don't poll on a timer — refresh only on tab focus / reconnect (cheap, and enough
    // to pick up a change made on another device the next time you look).
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
      setDoc(emptyLabelsDoc());
    };
  }, [keys, sessionToken, isAuthenticated]);

  // mutate reads the latest doc + version, applies fn, writes with CAS, and retries
  // on a version conflict (another device edited concurrently).
  const mutate = useCallback(async (fn: (d: LabelsDoc) => LabelsDoc) => {
    const store = storeRef.current;
    if (!store) return;
    for (let attempt = 0; attempt < 5; attempt++) {
      const { doc: cur, version } = await store.get();
      const next = fn(cur);
      try {
        await store.put(next, version);
        setDoc(next);
        return;
      } catch (e) {
        if (e instanceof StorageConflictError) continue; // re-read + retry
        throw e;
      }
    }
    throw new Error('labels: too many concurrent edits, please retry');
  }, []);

  const refreshLabels = useCallback(() => syncRef.current(), []);

  const createLabel = useCallback((name: string, color: string) =>
    mutate(d => ({ ...d, labels: [...d.labels, { id: newId(), name: name.trim(), color }] })), [mutate]);
  const renameLabel = useCallback((id: string, name: string, color?: string) =>
    mutate(d => ({ ...d, labels: d.labels.map(l => l.id === id ? { ...l, name: name.trim(), color: color ?? l.color } : l) })), [mutate]);
  const deleteLabel = useCallback((id: string) =>
    mutate(d => ({ ...d, labels: d.labels.filter(l => l.id !== id) })), [mutate]);

  const createFolder = useCallback((name: string) =>
    mutate(d => ({ ...d, folders: [...d.folders, { id: newId(), name: name.trim() }] })), [mutate]);
  const renameFolder = useCallback((id: string, name: string) =>
    mutate(d => ({ ...d, folders: d.folders.map(f => f.id === id ? { ...f, name: name.trim() } : f) })), [mutate]);
  const deleteFolder = useCallback((id: string) =>
    mutate(d => ({ ...d, folders: d.folders.filter(f => f.id !== id) })), [mutate]);

  const value: LabelsContextValue = {
    labels: doc.labels,
    folders: doc.folders,
    knownFolderIds: new Set(doc.folders.map(f => f.id)),
    labelById: (id) => doc.labels.find(l => l.id === id),
    folderById: (id) => doc.folders.find(f => f.id === id),
    refreshLabels,
    createLabel, renameLabel, deleteLabel,
    createFolder, renameFolder, deleteFolder,
  };

  return createElement(LabelsContext.Provider, { value }, children);
}

export function useLabels(): LabelsContextValue {
  const ctx = useContext(LabelsContext);
  if (!ctx) throw new Error('useLabels must be used within LabelsProvider');
  return ctx;
}
