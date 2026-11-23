import { describe, expect, it } from 'vitest';
import {
  asksAboutSender, autoFilingCandidates, filingChoices, filingDelta, filingSender, fullSwipeArchives,
  moved, movedTo, restoreRule, ruleFor, rulesByFolder, sameSenderMail, unfilingDelta, withRule, withoutRule,
  type Fileable, type SwipeFiling,
} from './filing';
import type { FlagRecord } from './api/flagStore';
import type { PlaceContext } from './mailView';

const ME = 'me@example.com';
const flag = (f: Partial<FlagRecord>): FlagRecord => ({ v: 1, updatedAt: 0, deviceId: '', ...f });
let n = 0;
const msg = (from: string, extra: Partial<Fileable> = {}): Fileable => ({
  hash: `h${++n}`, subject: 's', senderAddress: from, senderPublicKey: '', recipientAddress: ME,
  to: [ME], cc: [], sentAt: 1000, ...extra,
});
const ctx = (flags: Record<string, FlagRecord> = {}, folders = ['f1', 'f2']): PlaceContext => ({
  address: ME, flags: new Map(Object.entries(flags)), filter: null, control: new Set(), knownFolderIds: new Set(folders),
});

describe('settings defaults', () => {
  it('asks about the sender unless turned off, and full swipe deletes unless chosen', () => {
    expect(asksAboutSender(undefined)).toBe(true);
    expect(asksAboutSender({ asksAboutSender: false })).toBe(false);
    expect(fullSwipeArchives(undefined)).toBe(false);
    expect(fullSwipeArchives({ fullSwipeArchives: true })).toBe(true);
  });
});

describe('rules', () => {
  it('keeps one rule per sender, normalized, and keeps fields it does not know', () => {
    let sf: SwipeFiling = { asksAboutSender: false, other: 1 };
    sf = withRule(sf, ' Ada@Example.com ', 'f1', 10);
    sf = withRule(sf, 'ada@example.com', 'f2', 20);
    expect(sf.rules).toEqual([{ sender: 'ada@example.com', folderId: 'f2', since: 20 }]);
    expect(sf.other).toBe(1);
    expect(sf.asksAboutSender).toBe(false);
    expect(ruleFor(sf, 'ADA@example.com')?.folderId).toBe('f2');
    expect(withoutRule(sf, 'ada@example.com').rules).toEqual([]);
  });
  it('restores the earlier rule for Undo, or removes the new one', () => {
    const before = { sender: 'ada@example.com', folderId: 'f1', since: 5, extra: 'kept' };
    const sf = withRule({ rules: [before] }, 'ada@example.com', 'f2', 9);
    expect(restoreRule(sf, before, 'ada@example.com').rules).toEqual([before]);
    expect(restoreRule(sf, undefined, 'ada@example.com').rules).toEqual([]);
  });
  it('groups rules by folder in folder order, deleted folders last', () => {
    const sf: SwipeFiling = { rules: [
      { sender: 'b@x', folderId: 'f1', since: 0 }, { sender: 'a@x', folderId: 'f1', since: 0 },
      { sender: 'c@x', folderId: 'f2', since: 0 }, { sender: 'd@x', folderId: 'gone', since: 0 },
    ] };
    const groups = rulesByFolder(sf, [{ id: 'f2', name: 'Two' }, { id: 'f1', name: 'One' }]);
    expect(groups.map(g => g.folder?.id ?? null)).toEqual(['f2', 'f1', null]);
    expect(groups[1].rules.map(r => r.sender)).toEqual(['a@x', 'b@x']);
  });
});

describe('filingDelta', () => {
  it('back to the Inbox clears the archived mark too', () => {
    expect(filingDelta(undefined)).toEqual({ folderId: undefined, archived: undefined });
    expect('archived' in filingDelta(undefined)).toBe(true);
    expect(filingDelta('f1')).toEqual({ folderId: 'f1' });
  });
  it('undo puts folder and archive back as they were', () => {
    expect(unfilingDelta(flag({ folderId: 'f1', archived: true }))).toEqual({ folderId: 'f1', archived: true });
    expect(unfilingDelta(undefined)).toEqual({ folderId: undefined, archived: undefined });
  });
});

describe('filingSender', () => {
  it('follows a verified DMCN sender or ordinary email, never a key mismatch', () => {
    expect(filingSender({ senderAddress: 'A@x', senderPublicKey: 'ab' }, 'AB')).toBe('a@x');
    expect(filingSender({ senderAddress: 'a@x', senderPublicKey: 'ab' }, null)).toBe('a@x');
    expect(filingSender({ senderAddress: 'a@x', senderPublicKey: 'ab' }, 'cd')).toBeNull();
    expect(filingSender({ senderAddress: ' ', senderPublicKey: '' }, null)).toBeNull();
  });
});

describe('filingChoices', () => {
  const folders = [{ id: 'f1', name: 'One' }, { id: 'f2', name: 'Two' }];
  it('leaves out where the message already is', () => {
    expect(filingChoices('inbox', folders)).toEqual({ includeInbox: false, folders });
    expect(filingChoices('folder:f1', folders)).toEqual({ includeInbox: true, folders: [folders[1]] });
    expect(filingChoices('archive', folders).includeInbox).toBe(true);
  });
});

describe('sameSenderMail', () => {
  const senderOf = (m: Fileable) => filingSender(m, null);
  it('takes only the sender\'s mail from the same place', () => {
    const m = msg('ada@x');
    const inbox2 = msg('ADA@x');
    const filed = msg('ada@x');
    const archived = msg('ada@x');
    const other = msg('bob@x');
    const c = ctx({ [filed.hash]: flag({ folderId: 'f2' }), [archived.hash]: flag({ archived: true }) });
    const all = [m, inbox2, filed, archived, other];
    expect(sameSenderMail(m, 'f1', all, c, senderOf)).toEqual([inbox2.hash]);
    // From a folder, only that folder's mail comes along.
    expect(sameSenderMail(filed, 'f1', all, c, senderOf)).toEqual([]);
  });
  it('takes nothing when the message is already there, or in Archive', () => {
    const m = msg('ada@x');
    const a = msg('ada@x');
    const c = ctx({ [a.hash]: flag({ archived: true }) });
    expect(sameSenderMail(m, undefined, [m, msg('ada@x')], c, senderOf)).toEqual([]);
    expect(sameSenderMail(a, 'f1', [a, msg('ada@x')], c, senderOf)).toEqual([]);
  });
  it('leaves out a forged copy the sender check refuses', () => {
    const m = msg('ada@x', { senderPublicKey: 'aa' });
    const forged = msg('ada@x', { senderPublicKey: 'bb' });
    const real = (x: Fileable) => filingSender(x, 'aa');
    expect(sameSenderMail(m, 'f1', [m, forged], ctx(), real)).toEqual([]);
  });
});

describe('autoFilingCandidates', () => {
  const rules = [{ sender: 'ada@x', folderId: 'f1', since: 500 }];
  it('files untouched Inbox mail sent since the rule, to a folder that exists', () => {
    const fresh = msg('Ada@x', { sentAt: 600 });
    const old = msg('ada@x', { sentAt: 400 });
    const touched = msg('ada@x', { sentAt: 600 });
    const stranger = msg('bob@x', { sentAt: 600 });
    const c = ctx({ [touched.hash]: flag({ read: true }) });
    const got = autoFilingCandidates([fresh, old, touched, stranger], rules, c);
    expect(got.map(g => [g.hash, g.folderId])).toEqual([[fresh.hash, 'f1']]);
  });
  it('files nothing into a deleted folder', () => {
    expect(autoFilingCandidates([msg('ada@x', { sentAt: 600 })], rules, ctx({}, []))).toEqual([]);
  });
});

describe('reordering', () => {
  it('moves up and down within bounds', () => {
    expect(moved(['a', 'b', 'c'], 1, -1)).toEqual(['b', 'a', 'c']);
    expect(moved(['a', 'b', 'c'], 2, 1)).toEqual(['a', 'b', 'c']);
    expect(movedTo(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a']);
    expect(movedTo(['a', 'b', 'c'], 2, 9)).toEqual(['a', 'b', 'c']);
  });
});
