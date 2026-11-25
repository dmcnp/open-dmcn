import { describe, expect, it, vi } from 'vitest';
import type { Preview } from './api/mailboxRest';
import type { FlagRecord } from './api/flagStore';

vi.mock('@deployment', () => ({ deployment: { controlSubjects: [] } }));
const { countUnread } = await import('./unread');

const ME = 'me@x';
const msg = (hash: string): Preview => ({
  hash, messageId: '', threadId: '', senderAddress: 'ada@x', senderPublicKey: '', recipientAddress: ME,
  to: [ME], cc: [], bcc: [], subject: 's', snippet: '', senderDisplay: '', sentAt: 1, bodySize: 0, attachmentCount: 0,
} as Preview);
const flag = (f: Partial<FlagRecord>): FlagRecord => ({ v: 1, updatedAt: 0, deviceId: '', ...f });

describe('countUnread', () => {
  it('counts only unread mail the Inbox lists: not filed, archived, read or deleted', () => {
    const flags = new Map<string, FlagRecord>([
      ['filed', flag({ folderId: 'f1' })],
      ['archived', flag({ archived: true })],
      ['read', flag({ read: true })],
      ['deleted', flag({ trashedAt: 5 })],
    ]);
    const all = ['inbox', 'filed', 'archived', 'read', 'deleted'].map(msg);
    expect(countUnread(all, ME, flags, null, new Set(['f1']))).toBe(1);
  });

  it('counts mail filed in a folder that was deleted, which is back in the Inbox', () => {
    const flags = new Map([['filed', flag({ folderId: 'gone' })]]);
    expect(countUnread([msg('filed')], ME, flags, null, new Set())).toBe(1);
  });
});
