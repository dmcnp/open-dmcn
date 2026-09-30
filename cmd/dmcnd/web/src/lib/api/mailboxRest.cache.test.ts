// MailboxSync with the rows kept on this device: a second session draws the list before the relay
// answers and opens nothing to list it, yet a message is only ever opened from a header verified
// against this session's listing. Real envelopes and real crypto; the relay and IndexedDB are
// stand-ins.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { dmcn } from '@proto';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { Preview } from './mailboxRest';

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
  idbKeysWithPrefix: async (_s: string, prefix: string) => [...idb.keys()].filter(k => k.startsWith(prefix)),
  idbEntriesWithPrefix: async (_s: string, prefix: string) => [...idb.entries()].filter(([k]) => k.startsWith(prefix)),
}));
vi.mock('../crypto/retiredKeys', () => ({ retiredKeys: async () => [], asDecryptOnly: () => ({}) }));
vi.mock('./mailboxProof', () => ({ mailboxProof: async () => ({}) }));

// The relay: what the mailbox holds, and a gate the list waits on so a test can look at the page
// before the listing lands.
const relay = { entries: new Map<string, { entry: string; body: string }>(), gate: Promise.resolve(), lists: 0 };
vi.mock('./client', () => ({
  postJSONAs: async (_t: unknown, path: string, body: { op?: string; hash?: string; correlation_id?: string }) => {
    if (path.endsWith('/challenge')) return { correlation_id: `${body.op}:${body.hash ?? ''}`, nonce: '' };
    const [op, hash] = body.correlation_id!.split(':');
    if (op === 'list') {
      relay.lists++;
      await relay.gate;
      return { entries: [...relay.entries].map(([h, e]) => ({ hash: h, entry: e.entry })), next_cursor: '' };
    }
    if (op === 'body') return { hash, body: relay.entries.get(hash)!.body };
    if (op === 'delete') { relay.entries.delete(hash); return { hash }; }
    throw new Error('unexpected op ' + op);
  },
}));

const split = await import('../crypto/split');
const decryptHeader = vi.spyOn(split, 'decryptHeader');
const { MailboxSync } = await import('./mailboxRest');
const { generateIdentityKeyPair, importEd25519PrivateKey, importX25519PrivateKey, toBase64, toHex } = await import('../crypto/keys');

type KeyPair = Awaited<ReturnType<typeof generateIdentityKeyPair>>;

async function workingKeys(kp: KeyPair, address: string): Promise<WorkingKeys> {
  return {
    address,
    x25519Public: kp.x25519Public,
    x25519Derive: await importX25519PrivateKey(kp.x25519Private),
    aliasRoot: await crypto.subtle.importKey('raw', kp.ed25519Private.slice(0, 32), 'HKDF', false, ['deriveBits']),
  } as unknown as WorkingKeys;
}

let alice: KeyPair;
let bob: KeyPair;

async function deliver(subject: string, text: string): Promise<string> {
  const env = await split.encryptSplit({
    version: 1,
    messageId: crypto.getRandomValues(new Uint8Array(16)),
    threadId: crypto.getRandomValues(new Uint8Array(16)),
    senderAddress: 'alice@dmcn.localhost',
    senderPublicKey: alice.ed25519Public,
    senderSignKey: await importEd25519PrivateKey(alice.ed25519Private.slice(0, 32)),
    recipientAddress: 'bob@dmcn.localhost',
    to: ['bob@dmcn.localhost'],
    sentAt: 1_760_000_000 + relay.entries.size,
    subject,
    bodyText: text,
    recipients: [{ deviceId: bob.deviceId, x25519Pub: bob.x25519Public }],
  });
  const hash = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const entry = dmcn.relay.MailboxEntry.encode(dmcn.relay.MailboxEntry.create({
    recipients: env.recipients, encryptedHeader: env.encryptedHeader, headerNonce: env.headerNonce,
    headerTag: env.headerTag, headerSizeClass: env.headerSizeClass, bodyContentAddress: env.bodyContentAddress,
  })).finish();
  const body = dmcn.relay.MailboxBody.encode(dmcn.relay.MailboxBody.create({
    encryptedBody: env.encryptedBody, bodyNonce: env.bodyNonce, bodyTag: env.bodyTag, bodySizeClass: env.bodySizeClass,
  })).finish();
  relay.entries.set(hash, { entry: toBase64(entry), body: toBase64(body) });
  return hash;
}

// A session that lists once and has written what it saw, as an earlier unlock would have.
async function listedBefore(keys: WorkingKeys): Promise<void> {
  const { sync } = await session(keys);
  await sync.list();
  await sync.settled();
}

// A tab's session: the one that keeps the list on this device, unless told otherwise.
async function session(keys: WorkingKeys, writer = true) {
  const seen: Preview[][] = [];
  const sync = new MailboxSync(keys, p => seen.push(p));
  if (writer) await sync.becomeWriter();
  return { sync, seen };
}

beforeEach(async () => {
  idb.clear();
  relay.entries.clear();
  relay.gate = Promise.resolve();
  relay.lists = 0;
  decryptHeader.mockClear();
  alice = await generateIdentityKeyPair();
  bob = await generateIdentityKeyPair();
});

describe('MailboxSync with rows kept on this device', () => {
  it('draws the list from this device before the relay answers, and opens nothing to list it', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    await deliver('First', 'one');
    await deliver('Second', 'two');
    await listedBefore(keys);
    expect(decryptHeader).toHaveBeenCalledTimes(2);

    decryptHeader.mockClear();
    let open!: () => void;
    relay.gate = new Promise(r => { open = r; });
    const { sync, seen } = await session(keys);
    const listing = sync.list();
    await vi.waitFor(() => expect(seen.length).toBe(1));
    expect(seen[0].map(p => p.subject).sort()).toEqual(['First', 'Second']);
    open();
    await listing;
    expect(decryptHeader).not.toHaveBeenCalled();
  });

  it('opens a kept row from the verified header, and the body with it', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const hash = await deliver('Plans', 'The plan is to meet at noon.');
    await listedBefore(keys);

    decryptHeader.mockClear();
    const { sync } = await session(keys);
    await sync.list();
    const full = await sync.fetchFull(hash);
    expect(full.bodyText).toBe('The plan is to meet at noon.');
    expect(decryptHeader).toHaveBeenCalledTimes(1);
  });

  it('waits for a listing when a kept row is opened before one has landed', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const hash = await deliver('Early', 'opened straight away');
    await listedBefore(keys);

    const { sync } = await session(keys);
    let open!: () => void;
    relay.gate = new Promise(r => { open = r; });
    void sync.list().catch(() => undefined);
    const opening = sync.fetchFull(hash);
    open();
    expect((await opening).bodyText).toBe('opened straight away');
  });

  it('corrects a kept row to the header the relay serves', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const hash = await deliver('Genuine subject', 'body');
    await listedBefore(keys);

    // Rewrite the kept row (through the cache itself, since it is sealed) to say something else.
    const { PreviewCache } = await import('./previewCache');
    const pc = (await PreviewCache.open(keys, 'inbox'))!;
    const rows = (await pc.load()).rows;
    rows.set(hash, { preview: { ...rows.get(hash)!.preview, subject: 'Forged subject' } });
    await pc.save(rows);

    const { sync, seen } = await session(keys);
    await sync.list();
    expect(seen.at(-1)![0].subject).toBe('Forged subject'); // drawn, never trusted to open anything
    await sync.fetchFull(hash);
    expect(seen.at(-1)![0].subject).toBe('Genuine subject');
    const again = await session(keys);
    await again.sync.list();
    expect(again.seen.at(-1)![0].subject).toBe('Genuine subject');
  });

  it('drops kept rows for mail deleted elsewhere since', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const gone = await deliver('Gone', 'x');
    await deliver('Stays', 'y');
    await listedBefore(keys);
    relay.entries.delete(gone);

    const { sync } = await session(keys);
    const previews = await sync.list();
    expect(previews.map(p => p.subject)).toEqual(['Stays']);
    await expect(sync.fetchFull(gone)).rejects.toThrow(/no cached header/);
    const again = await session(keys);
    expect((await again.sync.list()).map(p => p.subject)).toEqual(['Stays']);
  });

  it('applies change events without listing, and keeps the result', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const first = await deliver('First', 'one');
    await deliver('Second', 'two');
    await listedBefore(keys);
    const third = await deliver('Third', 'three');

    relay.lists = 0;
    const { sync, seen } = await session(keys);
    await sync.showKept();
    await sync.applyEvents([
      { seq: 1, kind: 'mail_stored', hash: third, entry: relay.entries.get(third)!.entry },
      { seq: 2, kind: 'mail_deleted', hash: first },
      // Replayed: already applied, so nothing changes.
      { seq: 1, kind: 'mail_stored', hash: third, entry: relay.entries.get(third)!.entry },
    ]);
    expect(seen.at(-1)!.map(p => p.subject).sort()).toEqual(['Second', 'Third']);
    expect(relay.lists).toBe(0);

    const again = await session(keys);
    await again.sync.showKept();
    expect(again.seen.at(-1)!.map(p => p.subject).sort()).toEqual(['Second', 'Third']);
  });

  it('opens a kept message from its kept entry, without listing', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const hash = await deliver('Kept', 'opened from this device');
    await listedBefore(keys);

    relay.lists = 0;
    const { sync } = await session(keys);
    await sync.showKept();
    expect((await sync.fetchFull(hash)).bodyText).toBe('opened from this device');
    expect(relay.lists).toBe(0);
  });

  it('keeps the feed position with the rows, and drops it when rows are lost', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    for (let i = 0; i < 20; i++) await deliver(`Message ${i}`, 'x');
    await listedBefore(keys);
    const { sync } = await session(keys);
    await sync.setFeedPosition({ epoch: 'e1', seq: 42 });

    expect(await (await session(keys)).sync.feedPosition()).toEqual({ epoch: 'e1', seq: 42 });

    // A bucket that will not open means rows are missing, and only a listing puts them back.
    const bucket = [...idb.keys()].find(k => k.includes('::inbox/b/'))!;
    const other = [...idb.keys()].find(k => k.includes('::inbox/b/') && k !== bucket)!;
    idb.set(bucket, idb.get(other));
    expect(await (await session(keys)).sync.feedPosition()).toBeNull();
  });

  // Two tabs of one account share the store. The one that does not write must go on reading from
  // the position it started with, not from whatever the writer has moved the store to — or it
  // skips the events between, and keeps showing mail that was deleted.
  it('keeps each tab at its own position, and lets only the writer store one', async () => {
    const keys = await workingKeys(bob, 'bob@dmcn.localhost');
    const doomed = await deliver('Doomed', 'x');
    await deliver('Stays', 'y');
    const { sync: writer } = await session(keys);
    await writer.list();
    await writer.setFeedPosition({ epoch: 'e', seq: 1 });

    const { sync: reader, seen } = await session(keys, false);
    expect(await reader.feedPosition()).toEqual({ epoch: 'e', seq: 1 });

    await writer.applyEvents([{ seq: 2, kind: 'mail_deleted', hash: doomed }]);
    await writer.setFeedPosition({ epoch: 'e', seq: 2 });

    // The reader still stands where it read, so the delete reaches it as an event.
    expect(await reader.feedPosition()).toEqual({ epoch: 'e', seq: 1 });
    await reader.applyEvents([{ seq: 2, kind: 'mail_deleted', hash: doomed }]);
    expect(seen.at(-1)!.map(p => p.subject)).toEqual(['Stays']);

    // And nothing the reader does reaches the store.
    await reader.setFeedPosition({ epoch: 'e', seq: 99 });
    await reader.settled();
    expect(await (await session(keys, false)).sync.feedPosition()).toEqual({ epoch: 'e', seq: 2 });
  });
});

