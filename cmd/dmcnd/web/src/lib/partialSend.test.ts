import { describe, expect, it } from 'vitest';
import { partialSendMessage, reachedAudience, retryAudience } from './partialSend';

const failed = (...addresses: string[]) => addresses.map(address => ({ address, reason: `${address} failed.` }));
const all = { to: ['a@x', 'b@x'], cc: ['c@x'], bcc: ['d@x'] };

describe('reachedAudience', () => {
  it('lists everyone but those who failed', () => {
    expect(reachedAudience(all, failed('b@x', 'd@x'))).toEqual({ to: ['a@x'], cc: ['c@x'], bcc: [] });
  });
  it('matches an address however it was typed', () => {
    expect(reachedAudience(all, failed('B@X ')).to).toEqual(['a@x']);
  });
});

describe('retryAudience', () => {
  it('keeps only those who failed, where they were', () => {
    expect(retryAudience(all, failed('b@x', 'd@x'))).toEqual({ to: ['b@x'], cc: [], bcc: ['d@x'] });
  });
  it('moves a failed Cc up when To would be empty', () => {
    expect(retryAudience(all, failed('c@x'))).toEqual({ to: ['c@x'], cc: [], bcc: [] });
  });
  it('never moves a failed Bcc into To, which would show them', () => {
    expect(retryAudience(all, failed('d@x'))).toEqual({ to: [], cc: [], bcc: ['d@x'] });
  });
});

describe('partialSendMessage', () => {
  it('says who got it, why the rest did not, and what Send does now', () => {
    expect(partialSendMessage(['a@x'], failed('b@x', 'c@x'))).toBe(
      'This message reached a@x. b@x failed. c@x failed. Press Send to try again. It will go only to b@x, c@x.',
    );
  });
});
