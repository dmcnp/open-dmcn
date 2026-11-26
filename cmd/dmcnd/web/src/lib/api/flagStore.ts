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
  // Set when the owner deleted the message: unix ms. It sits in Deleted until restored (cleared)
  // or until the retention in settings has passed, when a client deletes it for good (lib/trash.ts).
  trashedAt?: number;
  updatedAt: number; // unix ms — recency for merge-on-read
  deviceId: string; // hex — tiebreak for equal updatedAt
}

export function flagKey(messageHash: string): string {
  return 'flags/' + messageHash;
}

// The mutable subset a caller can change in one edit.
export type FlagDelta = Partial<Pick<FlagRecord, 'read' | 'archived' | 'starred' | 'folderId' | 'labelIds' | 'trashedAt'>>;

export class FlagStore {
  private store: PersonalStore;
  private deviceHex: string;

  constructor(keys: WorkingKeys, explicitToken?: string) {
    this.store = new PersonalStore(keys, explicitToken);
    this.deviceHex = toHex(keys.deviceId);
  }

  // list returns every flag record, keyed by messageHash.
  async list(): Promise<Map<string, FlagRecord>> {
    return (await this.listTimed()).flags;
  }

  /**
   * Every flag record, and beside it when the relay recorded each one (unix ms), for the
   * records it has a time for.
   *
   * The two are kept apart on purpose. A flag record is written by whichever device changed it,
   * and a device may be allowed to do that without the account's signing key
   * (SPEC_EXT_DEVICES.md §3), so nothing inside one can be the basis for removing mail. The
   * relay's time can, because no writer chooses it.
   */
  async listTimed(): Promise<{ flags: Map<string, FlagRecord>; storedAt: Map<string, number> }> {
    const entries: StorageEntry<FlagRecord>[] = await this.store.list<FlagRecord>('flags/');
    const flags = new Map<string, FlagRecord>();
    const storedAt = new Map<string, number>();
    for (const e of entries) {
      // key is "flags/<hash>" — strip the namespace back to the message hash.
      const hash = e.key.startsWith('flags/') ? e.key.slice('flags/'.length) : e.key;
      flags.set(hash, e.value);
      if (e.writtenAt) storedAt.set(hash, e.writtenAt * 1000);
    }
    return { flags, storedAt };
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
      trashedAt: current?.trashedAt,
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
