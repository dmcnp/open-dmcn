import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { Preview } from './mailboxRest';

// IndexedDB as a Map, counting writes so a test can see how much a save rewrote.
const data = new Map<string, unknown>();
let puts = 0;
vi.mock('../crypto/idb', () => ({
  HEADERS_STORE: 'headers',
  idbGet: async (_s: string, k: string) => data.get(k),
  idbPutMany: async (_s: string, p: Array<[string, unknown]>, d: string[] = []) => {
    puts += p.length;
    for (const [k, v] of p) data.set(k, v);
    for (const k of d) data.delete(k);
  },
  idbDeletePrefix: async (_s: string, prefix: string) => {
    for (const k of [...data.keys()]) if (k.startsWith(prefix)) data.delete(k);
  },
  idbKeysWithPrefix: async (_s: string, prefix: string) => [...data.keys()].filter(k => k.startsWith(prefix)),
  idbEntriesWithPrefix: async (_s: string, prefix: string) =>
    [...data.entries()].filter(([k]) => k.startsWith(prefix)).sort(([a], [b]) => a.localeCompare(b)),
}));

const { PreviewCache, bucketOf, forgetPreviewCache } = await import('./previewCache');

async function keysFor(address: string, seed = 1): Promise<WorkingKeys> {
  const aliasRoot = await crypto.subtle.importKey('raw', new Uint8Array(32).fill(seed), 'HKDF', false, ['deriveBits']);
  return { address, aliasRoot } as unknown as WorkingKeys;
}

const row = (hash: string, subject = `subject of ${hash}`): { preview: Preview } => ({
  preview: {
    hash, messageId: '', threadId: '', senderAddress: 'alice@example.com', senderPublicKey: '',
    recipientAddress: 'bob@example.com', to: [], cc: [], bcc: [], subject, snippet: 'confidential snippet',
    senderDisplay: '', sentAt: 1, bodySize: 0, attachmentCount: 0,
  },
});

const rowsOf = (...hashes: string[]) => new Map(hashes.map(h => [h, row(h)]));

beforeEach(() => {
  data.clear();
  puts = 0;
});

describe('PreviewCache', () => {
  it('keeps rows across sessions, sealed', async () => {
    const pc = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    expect(((await pc.load()).rows).size).toBe(0);
    await pc.save(rowsOf('aa01', 'bb02'));

    const again = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    const loaded = (await again.load()).rows;
    expect([...loaded.keys()].sort()).toEqual(['aa01', 'bb02']);
    expect(loaded.get('aa01')!.preview.subject).toBe('subject of aa01');

    const dump = JSON.stringify([...data.values()], (_k, v) =>
      v instanceof ArrayBuffer || v instanceof Uint8Array ? new TextDecoder().decode(v) : v);
    expect(dump).not.toContain('confidential');
  });

  it('rewrites only the buckets that changed', async () => {
    const pc = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    await pc.load();
    const rows = new Map(Array.from({ length: 500 }, (_, i) => [`h${i}`, row(`h${i}`)]));
    await pc.save(rows);
    const full = puts;
    expect(full).toBeGreaterThan(100);

    puts = 0;
    await pc.save(new Map(rows)); // the same row objects: nothing to write
    expect(puts).toBe(0);

    rows.set('new', row('new'));
    await pc.save(new Map(rows));
    expect(puts).toBe(1);
  });

  it('drops removed rows, and a bucket left empty', async () => {
    const pc = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    await pc.load();
    await pc.save(rowsOf('only'));
    expect(data.has(`bob@example.com::inbox/b/${bucketOf('only')}`)).toBe(true);
    await pc.save(new Map());
    expect(data.has(`bob@example.com::inbox/b/${bucketOf('only')}`)).toBe(false);
    const again = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    expect(((await again.load()).rows).size).toBe(0);
  });

  it('starts again empty once the account key changes', async () => {
    const pc = (await PreviewCache.open(await keysFor('bob@example.com', 1), 'inbox'))!;
    await pc.load();
    await pc.save(rowsOf('aa01'));
    const rotated = (await PreviewCache.open(await keysFor('bob@example.com', 2), 'inbox'))!;
    expect(((await rotated.load()).rows).size).toBe(0);
    expect([...data.keys()].filter(k => k.includes('/b/'))).toEqual([]);
  });

  it('keeps Inbox and Sent, and accounts, apart', async () => {
    const inbox = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    await inbox.load();
    await inbox.save(rowsOf('aa01'));
    const sent = (await PreviewCache.open(await keysFor('bob@example.com'), 'sent'))!;
    expect(((await sent.load()).rows).size).toBe(0);
    const other = (await PreviewCache.open(await keysFor('carol@example.com'), 'inbox'))!;
    expect(((await other.load()).rows).size).toBe(0);

    await forgetPreviewCache('bob@example.com');
    expect([...data.keys()].some(k => k.startsWith('bob@example.com::'))).toBe(false);
    expect([...data.keys()].some(k => k.startsWith('carol@example.com::'))).toBe(true);
  });

  it('skips a bucket that will not open, rather than losing the rest', async () => {
    const pc = (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!;
    await pc.load();
    const rows = new Map(Array.from({ length: 50 }, (_, i) => [`h${i}`, row(`h${i}`)]));
    await pc.save(rows);
    const victim = `bob@example.com::inbox/b/${bucketOf('h0')}`;
    const other = [...data.keys()].find(k => k.includes('/b/') && k !== victim)!;
    data.set(victim, data.get(other)); // a record moved to another slot does not open
    const loaded = (await (await PreviewCache.open(await keysFor('bob@example.com'), 'inbox'))!.load()).rows;
    expect(loaded.has('h0')).toBe(false);
    expect(loaded.size).toBeGreaterThan(30);
  });

  it('is unavailable for keys too old to derive a key from', async () => {
    expect(await PreviewCache.open({ address: 'bob@example.com' } as unknown as WorkingKeys, 'inbox')).toBeNull();
  });
});
