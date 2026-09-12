import { describe, it, expect } from 'vitest';
import { arrivedAfterRetirement } from './mailboxRest';

// Retirement stops an address resolving, so no sender who looks it up can reach it. One holding a
// CACHED record still can, because STORE keys on the recipient key and never resolves. Those
// arrivals are discarded client-side — but only those.
describe('retired-address backstop', () => {
  const retired = new Map([['gone@dmcn.email', 1_700_000_000]]);

  it('discards mail that arrived after the address was retired', () => {
    expect(arrivedAfterRetirement('gone@dmcn.email', 1_700_000_001, retired)).toBe(true);
  });

  it('KEEPS mail that arrived before — that is history, not leakage', () => {
    expect(arrivedAfterRetirement('gone@dmcn.email', 1_699_999_999, retired)).toBe(false);
  });

  it('keeps mail that arrived at the exact instant, rather than guessing against the owner', () => {
    expect(arrivedAfterRetirement('gone@dmcn.email', 1_700_000_000, retired)).toBe(false);
  });

  it('is case-insensitive about the address', () => {
    expect(arrivedAfterRetirement('GONE@DMCN.EMAIL', 1_700_000_001, retired)).toBe(true);
  });

  it('leaves every live address alone', () => {
    expect(arrivedAfterRetirement('live@dmcn.email', 1_700_000_001, retired)).toBe(false);
    expect(arrivedAfterRetirement(undefined, 1_700_000_001, retired)).toBe(false);
    expect(arrivedAfterRetirement('gone@dmcn.email', 1_700_000_001, new Map())).toBe(false);
  });
});
