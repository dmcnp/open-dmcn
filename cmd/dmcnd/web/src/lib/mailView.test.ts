import { describe, expect, it } from 'vitest';
import { placeOf, type PlaceContext } from './mailView';
import { emptyFilterList } from './api/filterList';
import type { FlagRecord } from './api/flagStore';

const ME = 'me@example.com';

const msg = (hash: string, over: Partial<{ senderAddress: string; recipientAddress: string; subject: string; to: string[] }> = {}) => ({
  hash,
  senderAddress: 'alice@example.com',
  senderPublicKey: '',
  recipientAddress: ME,
  to: [ME],
  cc: [],
  subject: 'Hello',
  ...over,
});

const flag = (over: Partial<FlagRecord>): FlagRecord => ({ v: 1, updatedAt: 0, deviceId: '', ...over });

const ctx = (flags: Record<string, Partial<FlagRecord>> = {}, over: Partial<PlaceContext> = {}): PlaceContext => ({
  address: ME,
  flags: new Map(Object.entries(flags).map(([h, f]) => [h, flag(f)])),
  filter: emptyFilterList(),
  control: new Set(['control']),
  knownFolderIds: new Set(['f1']),
  ...over,
});

describe('placeOf', () => {
  it('puts received mail in the Inbox, Archive or its folder by its flags', () => {
    expect(placeOf(msg('a'), ctx())).toBe('inbox');
    expect(placeOf(msg('a'), ctx({ a: { archived: true } }))).toBe('archive');
    expect(placeOf(msg('a'), ctx({ a: { folderId: 'f1' } }))).toBe('folder:f1');
  });

  it('prefers the folder over Archive, and ignores a folder that no longer exists', () => {
    expect(placeOf(msg('a'), ctx({ a: { folderId: 'f1', archived: true } }))).toBe('folder:f1');
    expect(placeOf(msg('a'), ctx({ a: { folderId: 'gone' } }))).toBe('inbox');
  });

  it('puts what the account sent in Sent, but mail to itself in the Inbox', () => {
    expect(placeOf(msg('sent:m1', { senderAddress: ME, to: ['bob@example.com'] }), ctx())).toBe('sent');
    expect(placeOf(msg('legacy', { senderAddress: ME, recipientAddress: 'bob@example.com', to: ['bob@example.com'] }), ctx())).toBe('sent');
    expect(placeOf(msg('self', { senderAddress: ME }), ctx())).toBe('inbox');
  });

  it('puts deleted mail in Deleted whatever else it is filed under', () => {
    expect(placeOf(msg('a'), ctx({ a: { trashedAt: 1, archived: true, folderId: 'f1' } }))).toBe('deleted');
    expect(placeOf(msg('sent:m1', { senderAddress: ME }), ctx({ 'sent:m1': { trashedAt: 1 } }))).toBe('deleted');
  });

  it('leaves out control messages and blocked senders, deleted or not', () => {
    const blocked = { filter: { ...emptyFilterList(), senders: ['alice@example.com'] } };
    expect(placeOf(msg('a', { subject: 'control' }), ctx())).toBeNull();
    expect(placeOf(msg('a'), ctx({}, blocked))).toBeNull();
    expect(placeOf(msg('a'), ctx({ a: { trashedAt: 1 } }, blocked))).toBeNull();
    expect(placeOf(msg('a', { senderAddress: ME }), ctx({}, blocked))).toBe('inbox');
  });
});
