import { describe, it, expect } from 'vitest';
import { isFirstRun, type FirstRunInput } from './firstRun';

// Landing on Getting started (and the Inbox pointing there) is only for a mailbox that has never had
// mail in either direction, and only once that is known. Decided too early it sends a mailbox still
// loading to a beginner's page; decided on a cleared inbox it does the same to someone who is not new.

const fresh: FirstRunInput = { mailLoaded: true, sentLoaded: true, mailCount: 0, sentCount: 0, explained: false };

describe('isFirstRun', () => {
  it('shows for a mailbox that has never received or sent anything', () => {
    expect(isFirstRun(fresh)).toBe(true);
  });

  it('waits for both listings', () => {
    expect(isFirstRun({ ...fresh, mailLoaded: false })).toBe(false);
    expect(isFirstRun({ ...fresh, sentLoaded: false })).toBe(false);
  });

  it('steps aside once any mail exists, received or sent', () => {
    expect(isFirstRun({ ...fresh, mailCount: 1 })).toBe(false);
    expect(isFirstRun({ ...fresh, sentCount: 1 })).toBe(false);
  });

  it('leaves the explaining to whatever already explains an empty list', () => {
    expect(isFirstRun({ ...fresh, explained: true })).toBe(false);
  });
});
