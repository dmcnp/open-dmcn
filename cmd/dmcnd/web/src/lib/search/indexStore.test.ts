import { beforeEach, describe, expect, it, vi } from 'vitest';

// A Map for IndexedDB, with the one behaviour the index leans on: idbPutMany lands whole or not at
// all. The crypto is Node's real WebCrypto, so what is stored here is what a browser would store.
const data = new Map<string, unknown>();
let failNextPut = false;

vi.mock('../crypto/idb', () => ({
  SEARCH_STORE: 'search',
  idbGet: async (_s: string, k: string) => data.get(k),
  idbPutMany: async (_s: string, puts: Array<[string, unknown]>, deletes: string[] = []) => {
    if (failNextPut) { failNextPut = false; throw new Error('QuotaExceededError'); }
    for (const [k, v] of puts) data.set(k, v);
    for (const k of deletes) data.delete(k);
  },
  idbDeletePrefix: async (_s: string, prefix: string) => {
    for (const k of [...data.keys()]) if (k.startsWith(prefix)) data.delete(k);
  },
}));

const { SearchIndex, deriveSearchKey, forgetSearchIndex } = await import('./indexStore');

async function rootKey(seed: number): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(32).fill(seed), 'HKDF', false, ['deriveBits']);
}

async function openFor(address = 'alice@example.com', seed = 1) {
  return SearchIndex.open(address, await deriveSearchKey(await rootKey(seed), address));
}

beforeEach(() => {
  data.clear();
  failNextPut = false;
});

describe('SearchIndex', () => {
  it('finds a message by a word of its text, as a prefix, across a reopen', async () => {
    const idx = await openFor();
    await idx.add('h1', 'The quarterly invoice is attached');
    await idx.add('h2', 'Lunch on Friday?');
    await idx.flush();

    const again = await openFor();
    expect(again.size).toBe(2);
    expect([...await again.wordHits('invo')]).toEqual(['h1']);
    expect([...await again.wordHits('fri')]).toEqual(['h2']);
    expect((await again.wordHits('nothing')).size).toBe(0);
  });

  it('needs every word of a multi-word term', async () => {
    const idx = await openFor();
    await idx.add('h1', 'red car');
    await idx.add('h2', 'red bicycle');
    expect([...await idx.wordHits('red car')]).toEqual(['h1']);
    expect([...await idx.wordHits('red')].sort()).toEqual(['h1', 'h2']);
  });

  it('stores nothing readable', async () => {
    const idx = await openFor();
    await idx.add('h1', 'confidential merger terms', ['merger-plan.pdf']);
    await idx.flush();
    const dump = JSON.stringify([...data.values()], (_k, v) =>
      v instanceof ArrayBuffer ? new TextDecoder().decode(v) : v instanceof Uint8Array ? new TextDecoder().decode(v) : v);
    for (const secret of ['confidential', 'merger', 'h1']) expect(dump).not.toContain(secret);
  });

  it('keys every record to its slot, so shards cannot be swapped', async () => {
    const idx = await openFor();
    await idx.add('h1', 'invoice');
    await idx.add('h2', 'order');
    await idx.flush();
    const ns = 'alice@example.com::';
    const inv = data.get(ns + 's/in');
    data.set(ns + 's/in', data.get(ns + 's/or'));
    data.set(ns + 's/or', inv);
    const again = await openFor();
    await expect(again.wordHits('invoice')).rejects.toThrow();
  });

  it('is wiped and rebuilt when the account key no longer opens it', async () => {
    const idx = await openFor('alice@example.com', 1);
    await idx.add('h1', 'invoice');
    await idx.flush();
    const rotated = await openFor('alice@example.com', 2);
    expect(rotated.size).toBe(0);
    expect((await rotated.wordHits('invoice')).size).toBe(0);
    expect([...data.keys()].filter(k => k.includes('::s/'))).toEqual([]);
  });

  it('keeps accounts apart', async () => {
    const a = await openFor('alice@example.com');
    await a.add('h1', 'invoice');
    await a.flush();
    const b = await openFor('bob@example.com');
    expect((await b.wordHits('invoice')).size).toBe(0);
    await forgetSearchIndex('alice@example.com');
    expect([...data.keys()].every(k => k.startsWith('bob@example.com::'))).toBe(true);
  });

  it('matches attachment names by glob, including a leading wildcard', async () => {
    const idx = await openFor();
    await idx.add('h1', 'see attached', ['Scan 2026.PDF', 'notes.txt']);
    await idx.add('h2', 'see attached', ['photo.jpg']);
    await idx.flush();
    const again = await openFor();
    expect([...await again.filenameHits('*.pdf', /^.*\.pdf$/s)]).toEqual(['h1']);
    expect([...await again.filenameHits('photo', null)]).toEqual(['h2']);
    // Filenames are not body words.
    expect((await again.wordHits('scan')).size).toBe(0);
  });

  it('forgets removed messages at once and sweeps their postings on compaction', async () => {
    const idx = await openFor();
    await idx.add('h1', 'invoice alpha', ['a.pdf']);
    await idx.add('h2', 'invoice beta');
    await idx.remove(['h1']);
    await idx.flush();
    expect([...await idx.wordHits('invoice')]).toEqual(['h2']);
    expect((await idx.filenameHits('*.pdf', /^.*\.pdf$/s)).size).toBe(0);
    expect(idx.debugState().orphans).toBe(1);

    await idx.compact();
    expect(idx.debugState().orphans).toBe(0);
    expect(idx.debugState().shards).toEqual(['be', 'in']); // "alpha"'s shard emptied and went
    expect(data.has('alice@example.com::s/al')).toBe(false);
    const again = await openFor();
    expect([...await again.wordHits('invoice')]).toEqual(['h2']);
  });

  it('writes a flush whole or not at all', async () => {
    const idx = await openFor();
    await idx.add('h1', 'invoice');
    failNextPut = true;
    await expect(idx.flush()).rejects.toThrow();
    expect(idx.pending).toBe(true);
    const fresh = await openFor();
    expect(fresh.size).toBe(0);
    await idx.flush();
    expect((await openFor()).size).toBe(1);
  });

  it('does not index a message twice', async () => {
    const idx = await openFor();
    await idx.add('h1', 'invoice');
    await idx.add('h1', 'something else entirely');
    expect(idx.size).toBe(1);
    expect((await idx.wordHits('something')).size).toBe(0);
  });

  it('survives concurrent adds touching the same shards', async () => {
    const idx = await openFor();
    await Promise.all(Array.from({ length: 20 }, (_, i) => idx.add(`h${i}`, `invoice number${i}`)));
    await idx.flush();
    expect((await (await openFor()).wordHits('invoice')).size).toBe(20);
  });

  it('reload picks up what another tab wrote', async () => {
    const reader = await openFor();
    const writer = await openFor();
    await writer.add('h1', 'invoice');
    await writer.flush();
    expect((await reader.wordHits('invoice')).size).toBe(0);
    await reader.reload();
    expect([...await reader.wordHits('invoice')]).toEqual(['h1']);
  });
});
