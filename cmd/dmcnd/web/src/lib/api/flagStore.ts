// FlagStore is the extrinsic-metadata consumer of the personal storage substrate
// (TODO 10.3): per-message mutable state — read/unread, archived, starred, and
// (forward-compatible) folder/label assignment. Each message's state is ONE record
// under "flags/<messageHash>", sealed to the owner alone. Per-message records give a
// tiny blast radius: concurrent edits to different messages never collide, and the
// rare same-message race resolves last-writer-wins (see the plan's merge policy).

import { PersonalStore, type StorageEntry } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';
import { toHex } from '../crypto/keys';

export interface FlagRecord {
  v: number;
  read?: boolean;
  archived?: boolean;
  starred?: boolean;
  folderId?: string; // forward-compatible; folder assignment UI is a later increment
  labelIds?: string[]; // forward-compatible; label assignment UI is a later increment
  updatedAt: number; // unix ms — recency for merge-on-read
  deviceId: string; // hex — tiebreak for equal updatedAt
}

export function flagKey(messageHash: string): string {
  return 'flags/' + messageHash;
}

// The mutable subset a caller can change in one edit.
export type FlagDelta = Partial<Pick<FlagRecord, 'read' | 'archived' | 'starred' | 'folderId' | 'labelIds'>>;

export class FlagStore {
  private store: PersonalStore;
  private deviceHex: string;

  constructor(keys: WorkingKeys, explicitToken?: string) {
    this.store = new PersonalStore(keys, explicitToken);
    this.deviceHex = toHex(keys.deviceId);
  }

  // list returns every flag record, keyed by messageHash.
  async list(): Promise<Map<string, FlagRecord>> {
    const entries: StorageEntry<FlagRecord>[] = await this.store.list<FlagRecord>('flags/');
    const out = new Map<string, FlagRecord>();
    for (const e of entries) {
      // key is "flags/<hash>" — strip the namespace back to the message hash.
      const hash = e.key.startsWith('flags/') ? e.key.slice('flags/'.length) : e.key;
      out.set(hash, e.value);
    }
    return out;
  }

  // apply merges a delta onto the current record and writes it back. current is the
  // caller's latest known record (from the provider cache); the whole record is
  // replaced (last-writer-wins per message).
  async apply(messageHash: string, current: FlagRecord | undefined, delta: FlagDelta): Promise<FlagRecord> {
    const next: FlagRecord = {
      v: 1,
      read: current?.read,
      archived: current?.archived,
      starred: current?.starred,
      folderId: current?.folderId,
      labelIds: current?.labelIds,
      ...delta,
      updatedAt: Date.now(),
      deviceId: this.deviceHex,
    };
    // Unconditional write (expected_version = 0): the store holds one record per
    // message, so the last PUT wins — acceptable for high-churn per-message flags.
    await this.store.put(flagKey(messageHash), next);
    return next;
  }

  // remove deletes a message's flag record entirely (e.g. when the message is deleted).
  remove(messageHash: string): Promise<void> {
    return this.store.delete(flagKey(messageHash));
  }
}
