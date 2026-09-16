import { describe, expect, it } from 'vitest';
import { PULL_THRESHOLD, pullDistance } from './usePullToRefresh';

describe('pullDistance', () => {
  it('stays put until the gesture clears the slop', () => {
    expect(pullDistance(0)).toBe(0);
    expect(pullDistance(8)).toBe(0);
    expect(pullDistance(-40)).toBe(0);
  });

  it('tracks the finger one-to-one over the stretch that decides the outcome', () => {
    expect(pullDistance(8 + 20)).toBe(20);
    expect(pullDistance(8 + PULL_THRESHOLD)).toBe(PULL_THRESHOLD);
  });

  it('resists past the threshold and stops rather than following the finger off-screen', () => {
    expect(pullDistance(8 + PULL_THRESHOLD + 50)).toBeGreaterThan(PULL_THRESHOLD);
    expect(pullDistance(8 + PULL_THRESHOLD + 50)).toBeLessThan(PULL_THRESHOLD + 50);
    expect(pullDistance(8 + 2000)).toBe(96);
  });

  it('is a function of where the finger is, not how far it went — so a pull back up disarms', () => {
    // The caller compares the CURRENT distance with the threshold at release: a gesture that
    // reached 200px and returned to 30px is 30px, short of arming.
    expect(pullDistance(8 + 30)).toBeLessThan(PULL_THRESHOLD);
  });
});
