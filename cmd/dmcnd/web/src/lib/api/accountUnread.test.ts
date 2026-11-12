import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ApiError } from './bearer';
import type { WorkingKeys } from '../crypto/workingKeys';

// The background unread counter talks to the relay through three reads; each is stubbed so a
// test decides what the relay answers and counts how often it was asked.
const relay = { list: vi.fn(), flags: vi.fn(), login: vi.fn() };

vi.mock('./mailboxRest', () => ({
  MailboxSync: class { list() { return relay.list(); } },
}));
vi.mock('./flagStore', () => ({
  FlagStore: class { list() { return relay.flags(); } },
}));
vi.mock('./client', async () => ({
  ApiError: (await import('./bearer')).ApiError,
  loginWithKeys: (...args: unknown[]) => relay.login(...args),
}));
vi.mock('@deployment', () => ({
  deployment: { mailFilter: () => ({ get: async () => null }) },
}));
vi.mock('../unread', () => ({ countUnread: (previews: unknown[]) => previews.length }));

const { fetchAccountUnread, forgetAccountUnread, AccountLockedError } = await import('./accountUnread');

const wk = {} as WorkingKeys;
const closed = () => new ApiError('account access is closed', 403, 'access_closed');

describe('fetchAccountUnread', () => {
  beforeEach(() => {
    relay.list.mockReset();
    relay.flags.mockReset().mockResolvedValue([]);
    relay.login.mockReset().mockResolvedValue('tok');
  });

  it('stops asking the relay about an account it has closed', async () => {
    const address = 'closed@example.test';
    relay.list.mockRejectedValue(closed());

    await expect(fetchAccountUnread(address, wk)).rejects.toMatchObject({ code: 'access_closed' });
    expect(relay.list).toHaveBeenCalledTimes(1);
    expect(relay.login).toHaveBeenCalledTimes(1);

    // Every later poll answers locally: no token minted, no read sent.
    await expect(fetchAccountUnread(address, wk)).rejects.toBeInstanceOf(AccountLockedError);
    await expect(fetchAccountUnread(address, wk)).rejects.toBeInstanceOf(AccountLockedError);
    expect(relay.list).toHaveBeenCalledTimes(1);
    expect(relay.login).toHaveBeenCalledTimes(1);
  });

  it('asks again once the account is forgotten (sign-out, or switching to it)', async () => {
    const address = 'reopened@example.test';
    relay.list.mockRejectedValueOnce(closed()).mockResolvedValue([{}, {}]);

    await expect(fetchAccountUnread(address, wk)).rejects.toMatchObject({ code: 'access_closed' });
    forgetAccountUnread(address);
    await expect(fetchAccountUnread(address, wk)).resolves.toBe(2);
  });

  it('keeps polling through other failures', async () => {
    const address = 'flaky@example.test';
    relay.list.mockRejectedValueOnce(new ApiError('mailbox challenge failed', 502)).mockResolvedValue([{}]);

    await expect(fetchAccountUnread(address, wk)).rejects.toMatchObject({ status: 502 });
    await expect(fetchAccountUnread(address, wk)).resolves.toBe(1);
  });

  it('re-mints once on an expired session and counts', async () => {
    const address = 'expired@example.test';
    relay.list.mockRejectedValueOnce(new ApiError('invalid or expired session', 401)).mockResolvedValue([{}, {}, {}]);

    await expect(fetchAccountUnread(address, wk)).resolves.toBe(3);
    expect(relay.login).toHaveBeenCalledTimes(2);
  });

  it('remembers a lock first seen after re-minting', async () => {
    const address = 'expired-then-closed@example.test';
    relay.list.mockRejectedValueOnce(new ApiError('invalid or expired session', 401)).mockRejectedValue(closed());

    await expect(fetchAccountUnread(address, wk)).rejects.toMatchObject({ code: 'access_closed' });
    await expect(fetchAccountUnread(address, wk)).rejects.toBeInstanceOf(AccountLockedError);
    expect(relay.list).toHaveBeenCalledTimes(2);
  });
});
