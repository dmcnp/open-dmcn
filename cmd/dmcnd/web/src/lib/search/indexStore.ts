// The on-device search index: an inverted index over message text, kept in IndexedDB and
// encrypted under a key only the unlocked account can derive.
//
// Why it is shaped like this (the TODO that asked for it wanted the at-rest posture decided, not
// defaulted into):
//
//   - It persists, so locking does not throw away work. Indexing a mailbox means downloading
//     every body once, which on a mailbox of some years is gigabytes; that has to happen once per
//     device, not once per unlock. What a lock drops is the in-memory copy.
//   - It is encrypted, so persisting does not undo the lock: crypto/deviceSeal.ts, AES-GCM under a
//     key derived from the unlocked account, each record bound to its own slot.
//   - It is split into shards by the first two characters of each token, each sealed separately,
//     so a search decrypts only the shards its words start with: nothing is decrypted at unlock,
//     and the first keystroke of "invoice" opens the "in" shard and nothing else. The cost, and the
//     one thing this layout shows someone holding the device's storage, is each shard's size:
//     roughly how many of this mailbox's words start with each pair of letters.
//
// Records, under `<address>::`:
//   meta          deviceSeal's marker; if it no longer opens, the account's key changed (a
//                 rotation) and the index is rebuilt
//   manifest      sealed JSON   — which messages are indexed, as hash → document number
//   s/<shard>     sealed bytes  — shardIndex.ts's encoding of one shard
//   files         sealed JSON   — attachment filenames per document, whole (see filenameHits)
//
// Removing a message does not rewrite the shards it touched: its document number simply leaves the
// manifest, and a posting that names a number the manifest no longer has is ignored. compact()
// sweeps those out once there are enough of them to matter.

import { SEARCH_STORE, idbDeletePrefix, idbGet, idbPutMany } from '../crypto/idb';
import { deriveDeviceKey, keepIfOpens, seal, unseal, type Sealed } from '../crypto/deviceSeal';
import { tokenize, shardOf } from './tokenize';
import { addPosting, byShard, decodeShard, dropDocs, encodeShard, prefixDocs, type Shard } from './shardIndex';
import { filenameMatches } from './query';

const VERSION = 1;
/** Decoded shards kept in memory, by their encoded size. Past this, clean shards are dropped. */
const CACHE_BUDGET = 16 * 1024 * 1024;

interface ManifestJSON { v: number; next: number; docs: Array<[string, number]>; shards: string[]; orphans: number }

const enc = new TextEncoder();
const dec = new TextDecoder();

const nsOf = (address: string) => `${address.trim().toLowerCase()}::`;

/** Remove an account's index from this device (the account is being removed from it). */
export function forgetSearchIndex(address: string): Promise<void> {
  return idbDeletePrefix(SEARCH_STORE, nsOf(address));
}

/** The index key for one account (see crypto/deviceSeal.ts). */
export function deriveSearchKey(root: CryptoKey, address: string): Promise<CryptoKey> {
  return deriveDeviceKey(root, address, 'search');
}

export class SearchIndex {
  private readonly ns: string;
  private next = 0;
  private docs = new Map<string, number>(); // hash → doc
  private byDoc = new Map<number, string>(); // doc → hash
  private shardIds = new Set<string>();
  private orphans = 0;
  private cache = new Map<string, { shard: Shard; bytes: number }>(); // insertion order = LRU
  private loading = new Map<string, Promise<Shard>>();
  private dirty = new Set<string>();
  private files: Map<number, string[]> | null = null;
  private filesDirty = false;
  private manifestDirty = false;
  // Every mutation runs one at a time: add() loads shards across awaits, and a flush evicting one
  // of them in between would lose the postings added to the evicted copy.
  private chain: Promise<unknown> = Promise.resolve();

  private constructor(readonly address: string, private readonly key: CryptoKey) {
    this.ns = nsOf(address);
  }

  /**
   * Open (or start) an account's index. A stored index the key cannot open was written under a
   * previous key, and is wiped: it is a cache of the mailbox, and rebuilds from it.
   */
  static async open(address: string, key: CryptoKey): Promise<SearchIndex> {
    const idx = new SearchIndex(address, key);
    if (await keepIfOpens(SEARCH_STORE, idx.ns, key, VERSION)) await idx.loadManifest();
    return idx;
  }

  private run<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.chain.then(fn, fn);
    this.chain = p.catch(() => undefined);
    return p;
  }

  private seal(slot: string, plain: Uint8Array): Promise<Sealed> {
    return seal(this.key, this.ns + slot, plain);
  }

  private open(slot: string, s: Sealed): Promise<Uint8Array> {
    return unseal(this.key, this.ns + slot, s);
  }

  private async reset(): Promise<void> {
    await idbDeletePrefix(SEARCH_STORE, this.ns);
    this.next = 0;
    this.docs.clear();
    this.byDoc.clear();
    this.shardIds.clear();
    this.orphans = 0;
    this.cache.clear();
    this.loading.clear();
    this.dirty.clear();
    this.files = new Map();
    this.filesDirty = false;
    this.manifestDirty = false;
    await keepIfOpens(SEARCH_STORE, this.ns, this.key, VERSION);
  }

  private async loadManifest(): Promise<void> {
    const sealed = await idbGet<Sealed>(SEARCH_STORE, this.ns + 'manifest');
    this.docs.clear();
    this.byDoc.clear();
    this.shardIds.clear();
    this.next = 0;
    this.orphans = 0;
    if (!sealed) return;
    const m = JSON.parse(dec.decode(await this.open('manifest', sealed))) as ManifestJSON;
    this.next = m.next;
    this.orphans = m.orphans;
    for (const [hash, doc] of m.docs) { this.docs.set(hash, doc); this.byDoc.set(doc, hash); }
    for (const id of m.shards) this.shardIds.add(id);
  }

  /**
   * Forget everything held in memory and re-read the manifest: another tab has written the index.
   * Only a tab that is not writing calls this, so there is nothing unflushed to lose.
   */
  async reload(): Promise<void> {
    return this.run(async () => {
      this.cache.clear();
      this.loading.clear();
      this.files = null;
      await this.loadManifest();
    });
  }

  /** Messages indexed so far. */
  get size(): number { return this.docs.size; }

  has(hash: string): boolean { return this.docs.has(hash); }

  hashes(): IterableIterator<string> { return this.docs.keys(); }

  private shard(id: string): Promise<Shard> {
    const hit = this.cache.get(id);
    if (hit) {
      // Touch: re-inserting moves it to the young end of the LRU order.
      this.cache.delete(id);
      this.cache.set(id, hit);
      return Promise.resolve(hit.shard);
    }
    const pending = this.loading.get(id);
    if (pending) return pending;
    const p = (async () => {
      let shard: Shard = new Map();
      let bytes = 0;
      if (this.shardIds.has(id)) {
        const sealed = await idbGet<Sealed>(SEARCH_STORE, this.ns + 's/' + id);
        if (sealed) {
          const plain = await this.open('s/' + id, sealed);
          bytes = plain.length;
          shard = decodeShard(plain);
        }
      }
      // A copy that reached the cache while this one was loading is the live one: keep it.
      const raced = this.cache.get(id);
      if (raced) return raced.shard;
      this.cache.set(id, { shard, bytes });
      return shard;
    })().finally(() => this.loading.delete(id));
    this.loading.set(id, p);
    return p;
  }

  private async loadFiles(): Promise<Map<number, string[]>> {
    if (this.files) return this.files;
    const sealed = await idbGet<Sealed>(SEARCH_STORE, this.ns + 'files');
    const files = new Map<number, string[]>(
      sealed ? (JSON.parse(dec.decode(await this.open('files', sealed))) as Array<[number, string[]]>) : [],
    );
    this.files ??= files;
    return this.files;
  }

  /** Index one message's text and attachment names. A message already indexed is left alone. */
  add(hash: string, text: string, filenames: string[] = []): Promise<void> {
    return this.run(async () => {
      if (this.docs.has(hash)) return;
      const groups = byShard(tokenize(text));
      const shards = await Promise.all([...groups.keys()].map(id => this.shard(id)));
      const doc = this.next++;
      let k = 0;
      for (const [id, tokens] of groups) {
        const shard = shards[k++];
        for (const t of tokens) addPosting(shard, t, doc);
        this.shardIds.add(id);
        this.dirty.add(id);
      }
      const names = filenames.filter(Boolean);
      if (names.length) {
        (await this.loadFiles()).set(doc, names);
        this.filesDirty = true;
      }
      this.docs.set(hash, doc);
      this.byDoc.set(doc, hash);
      this.manifestDirty = true;
    });
  }

  /** Drop messages from the index (deleted, or their sender is now blocked). */
  remove(hashes: Iterable<string>): Promise<void> {
    return this.run(async () => {
      for (const hash of hashes) {
        const doc = this.docs.get(hash);
        if (doc === undefined) continue;
        this.docs.delete(hash);
        this.byDoc.delete(doc);
        this.orphans++;
        this.manifestDirty = true;
        const files = await this.loadFiles();
        if (files.delete(doc)) this.filesDirty = true;
      }
    });
  }

  /** Whether there is anything added or removed since the last flush. */
  get pending(): boolean { return this.manifestDirty || this.filesDirty || this.dirty.size > 0; }

  /** Write every change since the last flush, in one transaction. */
  flush(): Promise<void> {
    return this.run(() => this.flushNow());
  }

  private async flushNow(): Promise<void> {
    if (!this.pending) return;
    const puts: Array<[string, unknown]> = [];
    for (const id of this.dirty) {
      const hit = this.cache.get(id);
      if (!hit) continue;
      const bytes = encodeShard(hit.shard);
      hit.bytes = bytes.length;
      puts.push([this.ns + 's/' + id, await this.seal('s/' + id, bytes)]);
    }
    if (this.filesDirty && this.files) {
      puts.push([this.ns + 'files', await this.seal('files', enc.encode(JSON.stringify([...this.files])))]);
    }
    puts.push([this.ns + 'manifest', await this.seal('manifest', enc.encode(JSON.stringify(this.manifestJSON())))]);
    await idbPutMany(SEARCH_STORE, puts);
    this.dirty.clear();
    this.filesDirty = false;
    this.manifestDirty = false;
    this.evict();
  }

  private manifestJSON(): ManifestJSON {
    return { v: VERSION, next: this.next, docs: [...this.docs], shards: [...this.shardIds], orphans: this.orphans };
  }

  private evict(): void {
    let total = 0;
    for (const { bytes } of this.cache.values()) total += bytes;
    for (const [id, { bytes }] of this.cache) {
      if (total <= CACHE_BUDGET) break;
      if (this.dirty.has(id)) continue;
      this.cache.delete(id);
      total -= bytes;
    }
  }

  /** Whether enough removed messages linger in the shards that sweeping them is worth a rewrite. */
  get wantsCompaction(): boolean {
    return this.orphans > Math.max(500, this.docs.size / 4);
  }

  /**
   * Rewrite every shard without the postings of removed messages. Shard by shard, a few at a time,
   * so memory stays bounded; interrupted part way it is merely unfinished, since those postings
   * are ignored either way, and the orphan count only resets once every shard is clean.
   */
  compact(): Promise<void> {
    return this.run(async () => {
      await this.flushNow();
      const dead = (d: number) => !this.byDoc.has(d);
      const ids = [...this.shardIds];
      for (let i = 0; i < ids.length; i += 32) {
        const puts: Array<[string, unknown]> = [];
        const deletes: string[] = [];
        for (const id of ids.slice(i, i + 32)) {
          const shard = await this.shard(id);
          if (dropDocs(shard, dead) === 0) continue;
          if (shard.size === 0) {
            this.shardIds.delete(id);
            this.cache.delete(id);
            deletes.push(this.ns + 's/' + id);
          } else {
            const bytes = encodeShard(shard);
            const hit = this.cache.get(id);
            if (hit) hit.bytes = bytes.length;
            puts.push([this.ns + 's/' + id, await this.seal('s/' + id, bytes)]);
          }
        }
        if (puts.length || deletes.length) await idbPutMany(SEARCH_STORE, puts, deletes);
        this.evict();
      }
      this.orphans = 0;
      await idbPutMany(SEARCH_STORE, [[this.ns + 'manifest', await this.seal('manifest', enc.encode(JSON.stringify(this.manifestJSON())))]]);
    });
  }

  /** Throw the whole index away and start again empty. */
  clear(): Promise<void> {
    return this.run(() => this.reset());
  }

  /**
   * Messages whose text holds every word of term, each as a prefix of a word there ("invo" finds
   * "invoice"). A term with nothing indexable in it (one Latin letter, punctuation) finds nothing.
   */
  async wordHits(term: string): Promise<Set<string>> {
    const tokens = tokenize(term);
    if (tokens.length === 0) return new Set();
    let docs = null as Set<number> | null;
    for (const t of tokens) {
      const ids = [...t].length >= 2 ? [shardOf(t)] : [...this.shardIds].filter(id => id.startsWith(t));
      const found = new Set<number>();
      for (const id of ids) {
        if (!this.shardIds.has(id)) continue;
        for (const d of prefixDocs(await this.shard(id), t)) found.add(d);
      }
      docs = docs === null ? found : new Set([...docs].filter(d => found.has(d)));
      if (docs.size === 0) break;
    }
    return this.toHashes(docs ?? new Set());
  }

  /**
   * Messages with an attachment whose name matches: a glob when the value has a wildcard, else the
   * value anywhere in the name. Names are kept whole rather than tokenized so that a pattern can
   * start with a wildcard (`*.pdf`), which a prefix index cannot answer.
   */
  async filenameHits(value: string, glob: RegExp | null): Promise<Set<string>> {
    const files = await this.loadFiles();
    const docs = new Set<number>();
    for (const [doc, names] of files) if (names.some(n => filenameMatches(n, value, glob))) docs.add(doc);
    return this.toHashes(docs);
  }

  private toHashes(docs: Set<number>): Set<string> {
    const out = new Set<string>();
    for (const d of docs) {
      const h = this.byDoc.get(d);
      if (h !== undefined) out.add(h);
    }
    return out;
  }

  /** Test seam: every shard id currently stored, and whether it is in memory. */
  debugState(): { shards: string[]; cached: string[]; orphans: number } {
    return { shards: [...this.shardIds].sort(), cached: [...this.cache.keys()].sort(), orphans: this.orphans };
  }
}

