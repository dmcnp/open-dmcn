import { describe, expect, it } from 'vitest';
import { ApiError } from './api/bearer';
import { isRecipientClosed, lookupFailureKind, recipientClosedMessage } from './recipientLookup';

describe('lookupFailureKind', () => {
  it('reads only a 404 as ordinary email', () => {
    expect(lookupFailureKind(new ApiError('not found', 404))).toBe('legacy');
  });

  it('reads anything else as not checked, never as legacy', () => {
    expect(lookupFailureKind(new ApiError('could not reach', 502))).toBe('unchecked');
    expect(lookupFailureKind(new ApiError('gone', 410))).toBe('unchecked');
    expect(lookupFailureKind(new TypeError('Failed to fetch'))).toBe('unchecked');
    expect(lookupFailureKind(undefined)).toBe('unchecked');
  });
});

describe('isRecipientClosed', () => {
  it('is the 410 the send answers for a closed account', () => {
    expect(isRecipientClosed(new ApiError('recipient account is closed', 410))).toBe(true);
    expect(isRecipientClosed(new ApiError('recipient mailbox is full', 507))).toBe(false);
    expect(isRecipientClosed(new Error('boom'))).toBe(false);
  });

  it('names the address in plain words', () => {
    const msg = recipientClosedMessage('alice@dmcn.email');
    expect(msg).toContain('alice@dmcn.email');
    expect(msg).not.toMatch(/—|relay|STORE|410/);
  });
});
