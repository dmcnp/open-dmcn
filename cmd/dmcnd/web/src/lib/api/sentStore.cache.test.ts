// The Sent list with its rows kept on this device: drawn before the store answers, not reopened
// while the stored entry is unchanged, reopened when its version moves.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { WorkingKeys } from '../crypto/workingKeys';

const idb = new Map<string, unknown>();
vi.mock('../crypto/idb', () => ({
  HEADERS_STORE: 'headers',
  idbGet: async (_s: string, k: string) => idb.get(k),
  idbPutMany: async (_s: string, p: Array<[string, unknown]>, d: string[] = []) => {
    for (const [k, v] of p) idb.set(k, v);
    for (const k of d) idb.delete(k);
  },
  idbDeletePrefix: async (_s: string, prefix: string) => {
    for (const k of [...idb.keys()]) if (k.startsWith(prefix)) idb.delete(k);
  },
  idbEntriesWithPrefix: async (_s: string, prefix: string) => [...idb.entries()].filter(([k]) => k.startsWith(prefix)),
}));
vi.mock('../crypto/retiredKeys', () => ({ retiredKeys: async () => [], asDecryptOnly: () => ({}) }));

// The personal store: key → { value, version }.
const kv = new Map<string, { value: unknown; version: number }>();
vi.mock('./personalStore', () => ({
  PersonalStore: class {
    async list(prefix: string) {
      return [...kv].filter(([k]) => k.startsWith(prefix)).map(([key, r]) => ({ key, value: r.value, version: r.version }));
    }
    async get(key: string) {
      const r = kv.get(key);
      return r ? { key, value: r.value, version: r.version } : null;
    }
    async put(key: string, value: unknown) {
      kv.set(key, { value, version: (kv.get(key)?.version ?? 0) + 1 });
    }
    async delete(key: string) { kv.delete(key); }
  },
}));

const split = await import('../crypto/split');
const decryptHeader = vi.spyOn(split, 'decryptHeader');
const { SentStore } = await import('./sentStore');
const { generateIdentityKeyPair, importEd25519PrivateKey, importX25519PrivateKey, toHex } = await import('../crypto/keys');

let keys: WorkingKeys;
let signKey: CryptoKey;
let me: Awaited<ReturnType<typeof generateIdentityKeyPair>>;

async function sendOne(subject: string, text: string): Promise<string> {
  const messageId = crypto.getRandomValues(new Uint8Array(16));
  const env = await split.encryptSplit({
    version: 1, messageId, threadId: messageId,
    senderAddress: 'me@dmcn.localhost', senderPublicKey: me.ed25519Public, senderSignKey: signKey,
    recipientAddress: 'me@dmcn.localhost', to: ['you@dmcn.localhost'], sentAt: 1_760_000_000,
    subject, bodyText: text, recipients: [{ deviceId: me.deviceId, x25519Pub: me.x25519Public }],
  });
  await new SentStore(keys).putEnvelope(toHex(messageId), env);
  return 'sent:' + toHex(messageId);
}

beforeEach(async () => {
  idb.clear();
  kv.clear();
  me = await generateIdentityKeyPair();
  signKey = await importEd25519PrivateKey(me.ed25519Private.slice(0, 32));
  keys = {
    address: 'me@dmcn.localhost',
    x25519Public: me.x25519Public,
    x25519Derive: await importX25519PrivateKey(me.x25519Private),
    aliasRoot: await crypto.subtle.importKey('raw', me.ed25519Private.slice(0, 32), 'HKDF', false, ['deriveBits']),
  } as unknown as WorkingKeys;
  decryptHeader.mockClear();
});

describe('SentStore with rows kept on this device', () => {
  it('draws kept rows before listing, and does not reopen unchanged entries', async () => {
    await sendOne('Kept', 'hello');
    await new SentStore(keys).listPreviews();
    expect(decryptHeader).toHaveBeenCalledTimes(1);

    decryptHeader.mockClear();
    const store = new SentStore(keys);
    expect((await store.cachedPreviews()).map(p => p.subject)).toEqual(['Kept']);
    expect((await store.listPreviews()).map(p => p.subject)).toEqual(['Kept']);
    expect(decryptHeader).not.toHaveBeenCalled();
  });

  it('opens a kept row from the stored header, and its body', async () => {
    const hash = await sendOne('Kept', 'the body of it');
    await new SentStore(keys).listPreviews();

    const store = new SentStore(keys);
    await store.cachedPreviews();
    expect((await store.fetchFull(hash)).bodyText).toBe('the body of it');
  });

  it('reopens an entry whose stored version moved', async () => {
    const hash = await sendOne('Before', 'x');
    await new SentStore(keys).listPreviews();
    const mid = hash.slice('sent:'.length);
    const stored = kv.get('sent/' + mid)!;
    kv.set('sent/' + mid, { ...stored, version: stored.version + 1 });

    decryptHeader.mockClear();
    await new SentStore(keys).listPreviews();
    expect(decryptHeader).toHaveBeenCalledTimes(1);
  });

  it('forgets a deleted message on this device too', async () => {
    const hash = await sendOne('Doomed', 'x');
    const store = new SentStore(keys);
    await store.listPreviews();
    await store.delete(hash.slice('sent:'.length));
    await vi.waitFor(async () => expect(await new SentStore(keys).cachedPreviews()).toEqual([]));
  });
});
