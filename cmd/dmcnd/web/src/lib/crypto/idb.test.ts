import { beforeEach, describe, expect, it, vi } from 'vitest';

// A write is only durable once its transaction commits. Resolving on the request instead meant a
// readwrite that aborted afterwards — storage pressure, a serialization failure surfacing at
// commit — was reported as success and rolled back in silence. On a phone that showed up as
// several accounts' unlocked keys vanishing the instant after they were "stored", with nothing
// raised anywhere to say so.
//
// A hand-rolled IndexedDB stand-in rather than a dependency: the whole point is to drive the one
// ordering a real implementation will not produce on demand — request succeeds, transaction aborts.

interface Req { onsuccess?: () => void; onerror?: () => void; result?: unknown; error?: unknown }
interface Tx { oncomplete?: () => void; onabort?: () => void; onerror?: () => void; error?: unknown }

// How the next transaction should end: commit, or abort after its request has already succeeded.
let outcome: 'commit' | 'abort-after-success' = 'commit';
const data = new Map<string, unknown>();

function installFakeIndexedDB() {
  const store = {
    put(value: unknown, key: string): Req {
      const req: Req = {};
      queueMicrotask(() => { data.set(key, value); req.onsuccess?.(); });
      return req;
    },
    get(key: string): Req {
      const req: Req = {};
      queueMicrotask(() => { req.result = data.get(key); req.onsuccess?.(); });
      return req;
    },
    delete(key: string): Req {
      const req: Req = {};
      queueMicrotask(() => { data.delete(key); req.onsuccess?.(); });
      return req;
    },
  };
  const db = {
    objectStoreNames: { contains: () => true },
    createObjectStore: () => store,
    transaction() {
      const t: Tx = {};
      // The request resolves first, then the transaction ends — the ordering that matters.
      queueMicrotask(() => queueMicrotask(() => {
        if (outcome === 'commit') t.oncomplete?.();
        else { t.error = new Error('QuotaExceededError'); t.onabort?.(); }
      }));
      return { objectStore: () => store, ...t, set oncomplete(f: () => void) { t.oncomplete = f; },
        set onabort(f: () => void) { t.onabort = f; }, set onerror(f: () => void) { t.onerror = f; },
        get error() { return t.error; } };
    },
  };
  vi.stubGlobal('indexedDB', {
    open() {
      const req: Req & { onupgradeneeded?: () => void } = {};
      queueMicrotask(() => { req.result = db; req.onsuccess?.(); });
      return req;
    },
  });
}

beforeEach(() => {
  data.clear();
  outcome = 'commit';
  vi.resetModules();
  installFakeIndexedDB();
});

describe('idbPut', () => {
  it('resolves once the transaction commits', async () => {
    const { idbPut, idbGet, WORKING_STORE } = await import('./idb');
    await idbPut(WORKING_STORE, 'acct:a@x.test', { address: 'a@x.test' });
    expect(await idbGet(WORKING_STORE, 'acct:a@x.test')).toEqual({ address: 'a@x.test' });
  });

  // The regression: the request succeeded, so the old code resolved and the caller believed the
  // key was stored. The abort that followed rolled it back and said nothing.
  it('rejects when the transaction aborts after the request succeeded', async () => {
    const { idbPut, WORKING_STORE } = await import('./idb');
    outcome = 'abort-after-success';
    await expect(idbPut(WORKING_STORE, 'acct:a@x.test', { address: 'a@x.test' }))
      .rejects.toThrow(/aborted|Quota/i);
  });

  it('rejects a delete that does not commit', async () => {
    const { idbDelete, WORKING_STORE } = await import('./idb');
    outcome = 'abort-after-success';
    await expect(idbDelete(WORKING_STORE, 'acct:a@x.test')).rejects.toThrow(/aborted|Quota/i);
  });
});
