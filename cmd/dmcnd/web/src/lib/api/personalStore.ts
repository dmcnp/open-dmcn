// PersonalStore holds the owner's per-account mail state: Sent messages, read/unread + labels,
// contacts, and settings. Logical keys are "<namespace>/<id>" — e.g. "sent/<messageIdHex>",
// "flags/<messageHash>", "contacts/<id>", "settings/app"; list() takes a "<namespace>/" prefix.
//
// It is backed by the personal-storage ops on the owner's home relay, so this state follows the
// account between devices. Every value is SEALED TO THE OWNER in this browser before it is sent:
// the relay stores ciphertext it has no key for, and the server this client talks to never sees
// plaintext either. That is what makes it defensible to keep an address book on someone else's
// machine at all.
//
// A relay is not obliged to offer storage. One that does not answers UNSUPPORTED, and this store
// falls back to IndexedDB for the rest of the session — a minimal relay stays usable, at the cost
// of that account's state being single-device. That fallback is session-wide and SURFACED (see
// the signal below), because silently degrading to single-device state is indistinguishable from
// losing data. Nothing is copied up automatically in the other direction, because two devices
// that both went local would each have a divergent set and picking a winner is not ours to do.
//
// A per-key monotonic version supports optional compare-and-swap for singleton documents edited
// on more than one device.

import { idbGet, idbGetAllKeys, idbPut, idbDelete, PERSONAL_STORE } from '../crypto/idb';
import type { WorkingKeys } from '../crypto/workingKeys';
import { sealToRecipients, openSealed, type SealedBlobJSON } from '../crypto/sealedBlob';
import { signWithKey } from '../crypto/sign';
import { toBase64, fromBase64 } from '../crypto/keys';
import { postJSON, ApiError } from './client';

// StorageUsage is the owner's personal-storage occupancy for the Settings meter.
// quotaBytes === 0 means no cap.
export interface StorageUsage {
  usedBytes: number;
  quotaBytes: number;
  count: number;
}

// A decoded entry. value is the parsed plaintext object.
export interface StorageEntry<T> {
  key: string;
  value: T;
  version: number;
}

// StorageConflictError is thrown by put() when a compare-and-swap fails; the caller
// should re-read and retry.
export class StorageConflictError extends Error {
  constructor(msg = 'storage version conflict') {
    super(msg);
    this.name = 'StorageConflictError';
  }
}

// record is the physical shape stored in IndexedDB by the local fallback.
interface record<T> {
  value: T;
  version: number;
}

interface ChallengeResp { correlation_id: string; nonce: string }
interface KvGetResp { found: boolean; sealed?: string; version: number }
interface KvPutResp { version: number }
interface KvItemResp { key: string; sealed?: string; version: number }
interface KvListResp { items: KvItemResp[]; next_cursor?: string }
interface KvStatResp { used_bytes: number; quota_bytes: number; count: number }

// --- "this relay has no personal storage" signal -------------------------------------------
//
// The fallback used to be per-instance and entirely silent: each consumer (Sent, contacts,
// flags, settings) discovered UNSUPPORTED on its own, quietly switched to IndexedDB, and the
// person using it had no way to know their account state had stopped following them between
// devices. The way you found out was that a second device came up empty — which reads as data
// loss, not as a relay capability.
//
// So the discovery is hoisted to module scope: sticky for the session, shared by every store,
// and observable, so the shell can say it out loud. It also saves each later consumer a doomed
// round trip, since a new instance starts in local mode once any instance has learned it.
//
// Session-scoped on purpose — it is a fact about the relay we are talking to right now, and a
// reload (or signing into an account on a different home relay) should re-test rather than
// inherit a stale verdict.
let relayHasNoStorage = false;
const storageListeners = new Set<(v: boolean) => void>();

/** Whether the relay declined to host personal storage, so state is device-local this session. */
export function isStorageLocalOnly(): boolean {
  return relayHasNoStorage;
}

/** Subscribe to the flag; returns an unsubscribe. Fires only on the false → true transition. */
export function onStorageLocalOnly(fn: (v: boolean) => void): () => void {
  storageListeners.add(fn);
  return () => storageListeners.delete(fn);
}

function markStorageLocalOnly(): void {
  if (relayHasNoStorage) return;
  relayHasNoStorage = true;
  for (const fn of storageListeners) fn(true);
}

/** Test hook: clears the session verdict. */
export function resetStorageLocalOnlyForTest(): void {
  relayHasNoStorage = false;
}

export class PersonalStore {
  private keys: WorkingKeys;
  // The owner address namespaces the LOCAL fallback's keys within the shared per-origin store.
  // The relay namespaces by mailbox key on its side, so this is only for the fallback path.
  private owner: string;
  // Set once a relay tells us it has no storage. Seeded from the session-wide verdict so a
  // store created after the discovery never pays a failed round trip at all.
  private localOnly = isStorageLocalOnly();

  constructor(keys: WorkingKeys) {
    this.keys = keys;
    this.owner = keys.address;
  }

  // localOnlyMode reports whether this store fell back to device-local storage, so the UI can
  // say so rather than leaving someone to discover it when a second device is empty.
  get isLocalOnly(): boolean {
    return this.localOnly;
  }

  private ns(key: string): string {
    return this.owner + '::' + key;
  }

  // --- transport ---------------------------------------------------------------------------

  private async op<T>(req: Record<string, unknown>): Promise<T> {
    const ch = await postJSON<ChallengeResp>('/api/v1/mailbox/challenge', req);
    const signature = toBase64(await signWithKey(this.keys.ed25519Sign, fromBase64(ch.nonce)));
    return postJSON<T>('/api/v1/mailbox/complete', {
      correlation_id: ch.correlation_id,
      signature,
    });
  }

  // unsupported recognises the relay saying it hosts no storage, and latches the fallback —
  // for this instance and, so the UI can surface it, for the session.
  //
  // Deliberately narrow: only the definitive UNSUPPORTED/501 answer counts. A timeout or a 502
  // means "ask again later", and treating those as "no storage here" would strand an account on
  // device-local state because of one bad minute of network.
  private unsupported(err: unknown): boolean {
    if (err instanceof ApiError && (err.code === 'storage_unsupported' || err.status === 501)) {
      this.localOnly = true;
      markStorageLocalOnly();
      return true;
    }
    return false;
  }

  private async seal(obj: unknown): Promise<string> {
    const plain = new TextEncoder().encode(JSON.stringify(obj));
    const blob = await sealToRecipients(plain, [this.keys.x25519Public]);
    return toBase64(new TextEncoder().encode(JSON.stringify(blob)));
  }

  private async unseal<T>(sealedB64: string): Promise<T> {
    const blob = JSON.parse(new TextDecoder().decode(fromBase64(sealedB64))) as SealedBlobJSON;
    const plain = await openSealed(blob, this.keys.x25519Derive, this.keys.x25519Public);
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  }

  // --- public interface (unchanged for callers) ---------------------------------------------

  async get<T>(key: string): Promise<StorageEntry<T> | null> {
    if (!this.localOnly) {
      try {
        const res = await this.op<KvGetResp>({ op: 'kv_get', key });
        if (!res.found || !res.sealed) return null;
        return { key, value: await this.unseal<T>(res.sealed), version: res.version };
      } catch (err) {
        if (!this.unsupported(err)) throw err;
      }
    }
    const rec = await idbGet<record<T>>(PERSONAL_STORE, this.ns(key));
    if (!rec) return null;
    return { key, value: rec.value, version: rec.version };
  }

  async put(key: string, obj: unknown, expectedVersion = 0): Promise<number> {
    if (!this.localOnly) {
      try {
        const res = await this.op<KvPutResp>({
          op: 'kv_put', key, sealed: await this.seal(obj), expected_version: expectedVersion,
        });
        return res.version;
      } catch (err) {
        if (err instanceof ApiError && err.code === 'storage_conflict') {
          throw new StorageConflictError();
        }
        if (!this.unsupported(err)) throw err;
      }
    }
    const cur = await idbGet<record<unknown>>(PERSONAL_STORE, this.ns(key));
    const version = (cur?.version ?? 0) + 1;
    if (expectedVersion > 0 && (cur?.version ?? 0) !== expectedVersion) {
      throw new StorageConflictError();
    }
    await idbPut(PERSONAL_STORE, this.ns(key), { value: obj, version });
    return version;
  }

  async list<T>(prefix: string): Promise<StorageEntry<T>[]> {
    return this.listInternal<T>(prefix, true);
  }

  async listKeys(prefix: string): Promise<{ key: string; version: number }[]> {
    return (await this.listInternal<never>(prefix, false)).map(e => ({ key: e.key, version: e.version }));
  }

  private async listInternal<T>(prefix: string, withValues: boolean): Promise<StorageEntry<T>[]> {
    if (!this.localOnly) {
      try {
        const out: StorageEntry<T>[] = [];
        let cursor = '';
        // Paged: a mailbox with a long history has more Sent entries than one page holds, and
        // stopping at the first would silently truncate the folder.
        for (;;) {
          const res = await this.op<KvListResp>({
            op: 'kv_list', prefix, values: withValues, cursor,
          });
          for (const it of res.items) {
            if (!withValues) {
              out.push({ key: it.key, value: undefined as T, version: it.version });
              continue;
            }
            if (!it.sealed) continue;
            try {
              out.push({ key: it.key, value: await this.unseal<T>(it.sealed), version: it.version });
            } catch {
              // One unreadable blob must not take out the whole namespace — skip it and keep
              // the rest of the address book, folder or flag set usable.
            }
          }
          if (!res.next_cursor) break;
          cursor = res.next_cursor;
        }
        return out;
      } catch (err) {
        if (!this.unsupported(err)) throw err;
      }
    }
    const keys = await idbGetAllKeys(PERSONAL_STORE);
    const want = this.ns(prefix);
    const out: StorageEntry<T>[] = [];
    for (const k of keys) {
      const physical = String(k);
      if (!physical.startsWith(want)) continue;
      const rec = await idbGet<record<T>>(PERSONAL_STORE, physical);
      if (!rec) continue;
      out.push({
        key: physical.slice(this.owner.length + 2),
        value: withValues ? rec.value : (undefined as T),
        version: rec.version,
      });
    }
    return out;
  }

  async delete(key: string): Promise<void> {
    if (!this.localOnly) {
      try {
        await this.op<unknown>({ op: 'kv_delete', key });
        return;
      } catch (err) {
        if (!this.unsupported(err)) throw err;
      }
    }
    await idbDelete(PERSONAL_STORE, this.ns(key));
  }

  async stat(): Promise<StorageUsage> {
    if (!this.localOnly) {
      try {
        const res = await this.op<KvStatResp>({ op: 'kv_stat' });
        return { usedBytes: res.used_bytes, quotaBytes: res.quota_bytes, count: res.count };
      } catch (err) {
        if (!this.unsupported(err)) throw err;
      }
    }
    const keys = await idbGetAllKeys(PERSONAL_STORE);
    let usedBytes = 0;
    let count = 0;
    for (const k of keys) {
      const physical = String(k);
      if (!physical.startsWith(this.owner + '::')) continue;
      const rec = await idbGet<record<unknown>>(PERSONAL_STORE, physical);
      if (!rec) continue;
      count++;
      usedBytes += new TextEncoder().encode(JSON.stringify(rec.value)).length;
    }
    return { usedBytes, quotaBytes: 0, count };
  }
}
