// The mail list's rows, kept on this device between unlocks.
//
// The list is drawn from decrypted, signature-verified headers (Preview). Without this, every
// unlock started from nothing: download every header, and open and verify each one, before the
// first row could be drawn, which on a mailbox of some years is a long wait at a blank screen. With
// it, the rows an earlier session verified are shown at once, and a poll only has to open what is
// new since.
//
// Only the rows are kept, never what opens a message: the reader still fetches the header from the
// relay and verifies its signature before decrypting a body (MailboxSync.fetchFull), so nothing read
// back from this device is trusted with anything but drawing a row.
//
// Sealed like the search index (crypto/deviceSeal.ts): unreadable while the account is locked,
// wiped if the account re-keys. Rows are grouped into 256 buckets by a hash of the message hash,
// so a poll that brings one new message rewrites one bucket, not the list.

import type { Preview } from './mailboxRest';
import type { WorkingKeys } from '../crypto/workingKeys';
import { HEADERS_STORE, idbDeletePrefix, idbEntriesWithPrefix, idbPutMany } from '../crypto/idb';
import { deriveDeviceKey, keepIfOpens, seal, unseal, type Sealed } from '../crypto/deviceSeal';

const VERSION = 1;

export type PreviewScope = 'inbox' | 'sent';

export interface CachedRow {
  preview: Preview;
  /** The storage version the row was read at, for sources whose entries can change (Sent). */
  version?: number;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

const accountPrefix = (address: string) => `${address.trim().toLowerCase()}::`;

/** Remove an account's cached rows from this device (the account is being removed from it). */
export function forgetPreviewCache(address: string): Promise<void> {
  return idbDeletePrefix(HEADERS_STORE, accountPrefix(address));
}

// FNV-1a, folded to a byte: spreads hex hashes and "sent:" keys alike over the 256 buckets.
export function bucketOf(hash: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < hash.length; i++) {
    h ^= hash.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ((h ^ (h >>> 8) ^ (h >>> 16) ^ (h >>> 24)) & 0xff).toString(16).padStart(2, '0');
}

export class PreviewCache {
  // What the stored buckets hold, by hash, as last written or read. A save compares against it to
  // find the buckets that changed.
  private saved = new Map<string, CachedRow>();
  private chain: Promise<void> = Promise.resolve();

  private constructor(private readonly ns: string, private readonly key: CryptoKey) {}

  /** The cache for one account's Inbox or Sent list; null for keys too old to derive a key from. */
  static async open(keys: WorkingKeys, scope: PreviewScope): Promise<PreviewCache | null> {
    if (!keys.aliasRoot) return null;
    const key = await deriveDeviceKey(keys.aliasRoot, keys.address, 'headers');
    return new PreviewCache(`${accountPrefix(keys.address)}${scope}/`, key);
  }

  /** Every row stored. A bucket that will not open is skipped: its rows come back from the relay. */
  async load(): Promise<Map<string, CachedRow>> {
    this.saved = new Map();
    if (!(await keepIfOpens(HEADERS_STORE, this.ns, this.key, VERSION))) return new Map();
    for (const [slot, sealed] of await idbEntriesWithPrefix<Sealed>(HEADERS_STORE, this.ns + 'b/')) {
      try {
        const rows = JSON.parse(dec.decode(await unseal(this.key, slot, sealed))) as Array<[string, CachedRow]>;
        for (const [hash, row] of rows) this.saved.set(hash, row);
      } catch (err) {
        console.warn('list cache: skipping a bucket that will not open', slot, err);
      }
    }
    return new Map(this.saved);
  }

  /**
   * Make the stored rows exactly `rows`, rewriting only the buckets whose contents changed. A row
   * counts as unchanged when it is the same object that was saved (or loaded) last time, at the
   * same version — which is what the list sources hand back for a message they already held.
   */
  save(rows: Map<string, CachedRow>): Promise<void> {
    const next = this.chain.then(() => this.write(rows));
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async write(rows: Map<string, CachedRow>): Promise<void> {
    const dirty = new Set<string>();
    for (const [hash, row] of rows) {
      const was = this.saved.get(hash);
      if (!was || was.preview !== row.preview || was.version !== row.version) dirty.add(bucketOf(hash));
    }
    for (const hash of this.saved.keys()) if (!rows.has(hash)) dirty.add(bucketOf(hash));
    if (dirty.size === 0) return;

    const buckets = new Map<string, Array<[string, CachedRow]>>();
    for (const id of dirty) buckets.set(id, []);
    for (const [hash, row] of rows) buckets.get(bucketOf(hash))?.push([hash, row]);

    const puts: Array<[string, unknown]> = [];
    const deletes: string[] = [];
    for (const [id, list] of buckets) {
      const slot = this.ns + 'b/' + id;
      if (list.length === 0) deletes.push(slot);
      else puts.push([slot, await seal(this.key, slot, enc.encode(JSON.stringify(list)))]);
    }
    await idbPutMany(HEADERS_STORE, puts, deletes);
    this.saved = new Map(rows);
  }
}
