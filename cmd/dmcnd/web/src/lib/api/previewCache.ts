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
//
// Beside each row, in a record of its own, the list entry it was drawn from (the relay's header
// ciphertext, `raw`): what opening the message needs, so an unlock that learns of changes from
// the relay's change log, and never lists, can still open a message it did not see this session.
// Entries are never loaded with the rows — only read one at a time, when a message is opened —
// so they add storage but nothing to an unlock.

import type { Preview } from './mailboxRest';
import type { WorkingKeys } from '../crypto/workingKeys';
import { HEADERS_STORE, idbDeletePrefix, idbEntriesWithPrefix, idbGet, idbKeysWithPrefix, idbPutMany } from '../crypto/idb';
import { deriveDeviceKey, keepIfOpens, seal, unseal, type Sealed } from '../crypto/deviceSeal';
import type { FeedPosition } from '../sync/changes';

const VERSION = 1;

export type PreviewScope = 'inbox' | 'sent';

export interface CachedRow {
  preview: Preview;
  /** The storage version the row was read at, for sources whose entries can change (Sent). */
  version?: number;
  /** The list entry the row came from (base64), kept in its own record; see entry(). */
  raw?: string;
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
  // Messages whose list entry is stored, by hash. Read as keys at load, so an entry is written
  // once in its lifetime rather than again after every unlock.
  private withEntry = new Set<string>();
  // False when a bucket would not open at load: some rows are missing, so a change-feed position
  // kept beside them would skip the events that could have restored them (see load()).
  private intact = true;
  private full = false;
  private chain: Promise<void> = Promise.resolve();

  private constructor(private readonly ns: string, private readonly key: CryptoKey) {}

  /** The cache for one account's Inbox or Sent list; null for keys too old to derive a key from. */
  static async open(keys: WorkingKeys, scope: PreviewScope): Promise<PreviewCache | null> {
    if (!keys.aliasRoot) return null;
    const key = await deriveDeviceKey(keys.aliasRoot, keys.address, 'headers');
    return new PreviewCache(`${accountPrefix(keys.address)}${scope}/`, key);
  }

  /**
   * Every row stored, and the change-feed position they were written at. A bucket that will not
   * open is skipped (its rows come back from the relay) and then no position is returned, since
   * events past it could not restore what was lost.
   *
   * The position is read BEFORE the rows. Rows and position are written together, but read in two
   * steps, so another tab's write could land between them; this order means the rows are then
   * newer than the position, and replaying events over them is harmless — the other order would
   * skip events.
   */
  async load(): Promise<{ rows: Map<string, CachedRow>; position: FeedPosition | null }> {
    this.saved = new Map();
    this.withEntry = new Set();
    this.intact = true;
    if (!(await keepIfOpens(HEADERS_STORE, this.ns, this.key, VERSION))) return { rows: new Map(), position: null };
    const position = await this.readPosition();
    const entryPrefix = this.ns + 'e/';
    for (const k of await idbKeysWithPrefix(HEADERS_STORE, entryPrefix)) this.withEntry.add(k.slice(entryPrefix.length));
    for (const [slot, sealed] of await idbEntriesWithPrefix<Sealed>(HEADERS_STORE, this.ns + 'b/')) {
      try {
        const rows = JSON.parse(dec.decode(await unseal(this.key, slot, sealed))) as Array<[string, Omit<CachedRow, 'raw'>]>;
        for (const [hash, row] of rows) this.saved.set(hash, row);
      } catch (err) {
        this.intact = false;
        console.warn('list cache: skipping a bucket that will not open', slot, err);
      }
    }
    return { rows: new Map(this.saved), position: this.intact ? position : null };
  }

  private async readPosition(): Promise<FeedPosition | null> {
    const slot = this.ns + 'position';
    const sealed = await idbGet<Sealed>(HEADERS_STORE, slot);
    if (!sealed) return null;
    try {
      return JSON.parse(dec.decode(await unseal(this.key, slot, sealed))) as FeedPosition;
    } catch {
      return null;
    }
  }

  /**
   * Write every bucket on the next save, not only the ones this instance changed: what is stored
   * may be another tab's, and a snapshot is only consistent if it is all one writer's.
   */
  rewriteAll(): void {
    this.full = true;
  }

  /** Resolves once every save queued so far has been written (or has failed). */
  settled(): Promise<void> {
    return this.chain;
  }

  /** The list entry kept for one message, or undefined when none was. */
  async entry(hash: string): Promise<string | undefined> {
    const slot = this.ns + 'e/' + hash;
    const sealed = await idbGet<Sealed>(HEADERS_STORE, slot);
    if (!sealed) return undefined;
    try {
      return dec.decode(await unseal(this.key, slot, sealed));
    } catch {
      return undefined;
    }
  }

  /**
   * Make the stored rows exactly `rows`, rewriting only the buckets whose contents changed. A row
   * counts as unchanged when it is the same object that was saved (or loaded) last time, at the
   * same version — which is what the list sources hand back for a message they already held.
   */
  save(rows: Map<string, CachedRow>, position?: FeedPosition | null): Promise<void> {
    const next = this.chain.then(() => this.write(rows, position));
    this.chain = next.catch(() => undefined);
    return next;
  }

  // One transaction for the rows that changed, their entries and (when given) the position, so the
  // store always holds rows and a position from the same moment of the same writer.
  private async write(rows: Map<string, CachedRow>, position?: FeedPosition | null): Promise<void> {
    const dirty = new Set<string>();
    if (this.full) for (let i = 0; i < 256; i++) dirty.add(i.toString(16).padStart(2, '0'));
    let entries = false;
    for (const [hash, row] of rows) {
      const was = this.saved.get(hash);
      if (!was || was.preview !== row.preview || was.version !== row.version) dirty.add(bucketOf(hash));
      if (row.raw && !this.withEntry.has(hash)) entries = true;
    }
    for (const hash of this.saved.keys()) if (!rows.has(hash)) dirty.add(bucketOf(hash));
    if (dirty.size === 0 && !entries && position === undefined) return;

    const buckets = new Map<string, Array<[string, CachedRow]>>();
    for (const id of dirty) buckets.set(id, []);
    for (const [hash, row] of rows) buckets.get(bucketOf(hash))?.push([hash, row]);

    const puts: Array<[string, unknown]> = [];
    const deletes: string[] = [];
    for (const [id, list] of buckets) {
      const slot = this.ns + 'b/' + id;
      if (list.length === 0) deletes.push(slot);
      else puts.push([slot, await seal(this.key, slot, enc.encode(JSON.stringify(list.map(([h, r]) => [h, { preview: r.preview, version: r.version }]))))]);
    }
    // Entries: written once, when a row first arrives with one; removed with the row.
    const written: string[] = [];
    for (const [hash, row] of rows) {
      if (!row.raw || this.withEntry.has(hash)) continue;
      const slot = this.ns + 'e/' + hash;
      puts.push([slot, await seal(this.key, slot, enc.encode(row.raw))]);
      written.push(hash);
    }
    const dropped: string[] = [];
    for (const hash of this.withEntry) if (!rows.has(hash)) { deletes.push(this.ns + 'e/' + hash); dropped.push(hash); }
    if (position !== undefined) {
      const slot = this.ns + 'position';
      if (position === null) deletes.push(slot);
      else puts.push([slot, await seal(this.key, slot, enc.encode(JSON.stringify(position)))]);
    }
    await idbPutMany(HEADERS_STORE, puts, deletes);
    this.full = false;
    this.saved = new Map(rows);
    for (const h of written) this.withEntry.add(h);
    for (const h of dropped) this.withEntry.delete(h);
  }
}
