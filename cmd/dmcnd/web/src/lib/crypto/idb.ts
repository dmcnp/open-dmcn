// Minimal IndexedDB wrapper (no dependency). One database with four object stores:
//   - 'working'  — the unlocked, non-extractable CryptoKey handles (session-scoped)
//   - 'keystore' — the client-side encrypted blob + unlock metadata (persistent)
//   - 'personal' — the account's mail state (Sent, flags/labels, contacts, settings) when the
//                  home relay hosts no personal storage; see api/personalStore.ts
//   - 'pins'     — the device-local counterparty key pins (persistent, see trust/pinStore.ts)
//
// We store structured-cloneable values directly (CryptoKey objects survive the
// clone with their bytes never serialized into JS reach). Keys are simple strings.
//
// The earlier note here said the first two stores were the ENTIRE local footprint —
// mail, contacts and flags all live in the personal KV and are only ever decrypted in
// memory — so naming the database per context was all it took to make an installed app
// its own device, and it asked that a third store re-open that reasoning. 'pins' is
// that third store, and it does:
//
//   - It must be local BECAUSE the personal KV is served by the relay. A pin whose only
//     copy sits in the KV can be withheld or rolled back by the very operator it exists
//     to detect, which makes it no defence at all against a hostile fleet. The KV copy
//     is kept for cross-device sync; this one is the source of truth.
//   - Per-context separation is still the right default, and it comes for free from
//     DB_NAME. A pin is an observation this device made; an installed app that never
//     saw a contact has no honest basis for claiming a pin on them. The cost is that a
//     fresh context adopts the KV's pins once, on first sight — the same exposure any
//     new device has, and documented as such in trust/pinStore.ts.

import { usesOwnStore } from '../appContext';

// Resolved once at module load: a window can't move between contexts mid-session, and
// pinning stops a display-mode change from re-pointing the database under an open
// transaction.
const DB_NAME = usesOwnStore() ? 'dmcn-app' : 'dmcn';
// v2 added PINS_STORE; v3 added PERSONAL_STORE. onupgradeneeded creates only the stores
// that are missing, so an existing database keeps its working handles, keystore and pins
// across either bump.
const DB_VERSION = 3;
export const WORKING_STORE = 'working';
export const KEYSTORE_STORE = 'keystore';
export const PERSONAL_STORE = 'personal';
export const PINS_STORE = 'pins';

let dbPromise: Promise<IDBDatabase> | null = null;

function openDB(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(WORKING_STORE)) db.createObjectStore(WORKING_STORE);
      if (!db.objectStoreNames.contains(KEYSTORE_STORE)) db.createObjectStore(KEYSTORE_STORE);
      if (!db.objectStoreNames.contains(PERSONAL_STORE)) db.createObjectStore(PERSONAL_STORE);
      if (!db.objectStoreNames.contains(PINS_STORE)) db.createObjectStore(PINS_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

function tx<T>(store: string, mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDB().then(
    db =>
      new Promise<T>((resolve, reject) => {
        const t = db.transaction(store, mode);
        const req = fn(t.objectStore(store));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      })
  );
}

export function idbGet<T>(store: string, key: string): Promise<T | undefined> {
  return tx<T | undefined>(store, 'readonly', s => s.get(key) as IDBRequest<T | undefined>);
}

export function idbGetAll<T>(store: string): Promise<T[]> {
  return tx<T[]>(store, 'readonly', s => s.getAll() as IDBRequest<T[]>);
}

export function idbGetAllKeys(store: string): Promise<string[]> {
  return tx<string[]>(store, 'readonly', s => s.getAllKeys() as unknown as IDBRequest<string[]>);
}

export function idbPut(store: string, key: string, value: unknown): Promise<void> {
  return tx(store, 'readwrite', s => s.put(value, key)).then(() => undefined);
}

export function idbDelete(store: string, key: string): Promise<void> {
  return tx(store, 'readwrite', s => s.delete(key)).then(() => undefined);
}
