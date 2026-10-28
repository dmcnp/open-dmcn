// Drafts against an in-memory personal store with the relay's compare-and-swap rules, and an
// in-memory device copy.
import { describe, it, expect } from 'vitest';
import {
  DraftStore, DraftConflictError, NEW_DRAFT_BASE, LOCAL_SETTLE_MS, draftHasContent, draftSnippet, inlinePreviews,
  type DraftBackstop, type DraftContent, type DraftKv,
} from './draftStore';
import { StorageConflictError, type StorageEntry } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { AttachmentInput } from '../crypto/split';

function memoryKv() {
  const data = new Map<string, { value: unknown; version: number }>();
  const writes: string[] = [];
  const kv: DraftKv = {
    async get<T>(key: string): Promise<StorageEntry<T> | null> {
      const r = data.get(key);
      return r ? { key, value: structuredClone(r.value) as T, version: r.version } : null;
    },
    async put(key: string, obj: unknown, expectedVersion = 0): Promise<number> {
      const cur = data.get(key)?.version ?? 0;
      if (expectedVersion !== 0 && cur !== expectedVersion) throw new StorageConflictError();
      data.set(key, { value: structuredClone(obj), version: cur + 1 });
      writes.push(key);
      return cur + 1;
    },
    async list<T>(prefix: string): Promise<StorageEntry<T>[]> {
      return [...data].filter(([k]) => k.startsWith(prefix)).map(([key, r]) => ({ key, value: structuredClone(r.value) as T, version: r.version }));
    },
    async listKeys(prefix: string) {
      return [...data].filter(([k]) => k.startsWith(prefix)).map(([key, r]) => ({ key, version: r.version }));
    },
    async delete(key: string) { data.delete(key); },
  };
  return { kv, data, writes };
}

function memoryBackstop(): DraftBackstop & { map: Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    map,
    async get(key) { return structuredClone(map.get(key)) as never; },
    async put(key, value) { map.set(key, structuredClone(value)); },
    async delete(key) { map.delete(key); },
    async entries(prefix) { return [...map].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => [k, structuredClone(v)] as never); },
  };
}

const keys = { address: 'me@dmcn.localhost' } as WorkingKeys;

function att(n: number, extra: Partial<AttachmentInput> = {}): AttachmentInput {
  return {
    attachmentId: new Uint8Array(16).fill(n),
    filename: `file${n}.pdf`,
    contentType: 'application/pdf',
    sizeBytes: 3,
    contentHash: new Uint8Array(32).fill(n),
    content: new Uint8Array([n, n, n]),
    ...extra,
  };
}

function content(over: Partial<DraftContent> = {}): DraftContent {
  return {
    from: 'me@dmcn.localhost', to: ['you@dmcn.localhost'], cc: [], bcc: [],
    pending: { to: '', cc: '', bcc: '' }, showCcBcc: false,
    subject: 'Plans', rich: false, text: 'Half a thought', html: '', replyTo: null, attachments: [],
    ...over,
  };
}

describe('DraftStore', () => {
  it('round-trips a draft with its attachments through the relay', async () => {
    const { kv } = memoryKv();
    const store = new DraftStore(keys, { keepLocal: false, kv });
    const c = content({ attachments: [att(1), att(2, { contentId: 'img@dmcn', disposition: 'inline' })], bcc: ['hidden@dmcn.localhost'] });
    const base = await store.save('d1', c, NEW_DRAFT_BASE, 1000);
    expect(base.atts).toHaveLength(2);

    const loaded = await store.load('d1');
    expect(loaded?.content).toEqual(c);
    expect(loaded?.base).toEqual(base);
    expect(await store.list()).toEqual([expect.objectContaining({ id: 'd1', subject: 'Plans', snippet: 'Half a thought', attachmentCount: 2, bcc: ['hidden@dmcn.localhost'] })]);
  });

  it('uploads an attachment once and deletes it when it is taken out', async () => {
    const { kv, data, writes } = memoryKv();
    const store = new DraftStore(keys, { keepLocal: false, kv });
    let base = await store.save('d1', content({ attachments: [att(1)] }), NEW_DRAFT_BASE, 1000);
    base = await store.save('d1', content({ text: 'more', attachments: [att(1)] }), base, 2000);
    expect(writes.filter(k => k.startsWith('draft-att/')).length).toBe(1);

    base = await store.save('d1', content({ attachments: [] }), base, 3000);
    expect([...data.keys()].some(k => k.startsWith('draft-att/'))).toBe(false);
    expect(base.atts).toEqual([]);
  });

  it('refuses to overwrite a copy another device saved, unless told to', async () => {
    const { kv } = memoryKv();
    const here = new DraftStore(keys, { keepLocal: false, kv });
    const there = new DraftStore(keys, { keepLocal: false, kv });
    const base = await here.save('d1', content(), NEW_DRAFT_BASE, 1000);
    await there.save('d1', content({ text: 'from the phone' }), base, 2000);

    await expect(here.save('d1', content({ text: 'from the laptop' }), base, 3000)).rejects.toBeInstanceOf(DraftConflictError);
    expect((await here.load('d1'))?.content.text).toBe('from the phone');

    await here.save('d1', content({ text: 'from the laptop' }), base, 3000, true);
    expect((await here.load('d1'))?.content.text).toBe('from the laptop');
  });

  it('treats a draft sent elsewhere as a conflict, not a new draft', async () => {
    const { kv } = memoryKv();
    const store = new DraftStore(keys, { keepLocal: false, kv });
    const base = await store.save('d1', content(), NEW_DRAFT_BASE, 1000);
    await store.delete('d1');
    await expect(store.save('d1', content(), base, 2000)).rejects.toBeInstanceOf(DraftConflictError);
    expect(await store.list()).toEqual([]);
  });

  it('delete removes the row, the body and every attachment', async () => {
    const { kv, data } = memoryKv();
    const store = new DraftStore(keys, { keepLocal: false, kv });
    await store.save('d1', content({ attachments: [att(1), att(2)] }), NEW_DRAFT_BASE, 1000);
    await store.delete('d1');
    expect(data.size).toBe(0);
  });

  it('lists and opens the device copy of a draft the relay never got', async () => {
    const { kv } = memoryKv();
    const backstop = memoryBackstop();
    const store = new DraftStore(keys, { keepLocal: true, kv, backstop });
    await store.saveLocal('d1', content({ text: 'written offline' }), NEW_DRAFT_BASE, 1000);
    expect((await store.list()).map(d => d.snippet)).toEqual(['written offline']);
    expect((await store.load('d1'))?.content.text).toBe('written offline');
  });

  it('settles a device copy once it has gone quiet, and leaves a fresh one alone', async () => {
    const { kv } = memoryKv();
    const backstop = memoryBackstop();
    const store = new DraftStore(keys, { keepLocal: true, kv, backstop });
    await store.saveLocal('old', content({ text: 'old' }), NEW_DRAFT_BASE, 1000);
    await store.saveLocal('new', content({ text: 'new' }), NEW_DRAFT_BASE, 1000 + LOCAL_SETTLE_MS);

    expect(await store.settleLocal(new Set(), 1000 + LOCAL_SETTLE_MS + 1)).toBe(true);
    expect([...backstop.map.keys()]).toEqual(['draft::me@dmcn.localhost::new']);
    expect((await kv.get<{ snippet: string }>('drafts/old'))?.value.snippet).toBe('old');
  });

  it('drops a device copy of a draft that was sent or discarded elsewhere', async () => {
    const { kv } = memoryKv();
    const backstop = memoryBackstop();
    const store = new DraftStore(keys, { keepLocal: true, kv, backstop });
    const base = await store.save('d1', content(), NEW_DRAFT_BASE, 1000);
    await store.saveLocal('d1', content({ text: 'edited offline' }), base, 2000);
    await new DraftStore(keys, { keepLocal: false, kv }).delete('d1');

    expect(await store.list()).toEqual([]);
    await store.settleLocal(new Set(), 2000 + LOCAL_SETTLE_MS);
    expect(backstop.map.size).toBe(0);
  });

  it('clearLocal keeps a device copy newer than the save that finished', async () => {
    const backstop = memoryBackstop();
    const store = new DraftStore(keys, { keepLocal: true, kv: memoryKv().kv, backstop });
    await store.saveLocal('d1', content({ text: 'newer' }), NEW_DRAFT_BASE, 2000);
    await store.clearLocal('d1', 1000);
    expect(backstop.map.size).toBe(1);
    await store.clearLocal('d1', 2000);
    expect(backstop.map.size).toBe(0);
  });

  it('keeps nothing on the device in a temporary session', async () => {
    const backstop = memoryBackstop();
    const store = new DraftStore(keys, { keepLocal: false, kv: memoryKv().kv, backstop });
    await store.saveLocal('d1', content(), NEW_DRAFT_BASE, 1000);
    expect(backstop.map.size).toBe(0);
  });
});

describe('draft helpers', () => {
  it('a composer opened and closed again holds nothing', () => {
    const empty = content({ to: [], subject: '', text: '\n\n-- \nMe' });
    expect(draftHasContent(empty, '\n\n-- \nMe')).toBe(false);
    expect(draftHasContent({ ...empty, subject: 'Hi' }, '\n\n-- \nMe')).toBe(true);
    expect(draftHasContent({ ...empty, pending: { to: 'som', cc: '', bcc: '' } }, '\n\n-- \nMe')).toBe(true);
  });

  it('an untouched reply holds nothing, despite its recipients and subject', () => {
    const reply = content({ subject: 'Re: Plans', text: '\n\n> quoted', replyTo: { to: ['you@dmcn.localhost'], subject: 'Plans' } });
    expect(draftHasContent(reply, '\n\n> quoted')).toBe(false);
    expect(draftHasContent({ ...reply, text: 'Sure\n\n> quoted' }, '\n\n> quoted')).toBe(true);
  });

  it('snippets fold whitespace and stop', () => {
    expect(draftSnippet('  a\n\n b  ')).toBe('a b');
    expect(draftSnippet('x'.repeat(500)).length).toBe(140);
  });

  it('puts inline images back on screen and leaves unknown ones as they are', () => {
    const img = att(7, { contentId: 'pic@dmcn', disposition: 'inline', contentType: 'image/png' });
    const out = inlinePreviews('<img src="cid:pic@dmcn" alt="a"><img src="cid:gone@dmcn">', [img]);
    expect(out).toBe('<img src="data:image/png;base64,BwcH" data-cid="pic@dmcn" alt="a"><img src="cid:gone@dmcn">');
  });
});
