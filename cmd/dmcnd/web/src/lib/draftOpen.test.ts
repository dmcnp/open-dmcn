import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isDraftOpen, onDraftOpenChange, setDraftOpen } from './draftOpen';

// This flag is what stops a tapped notification switching accounts out from under an unsent
// message, which would discard it. The deferral hangs entirely on subscribers being told when the
// draft closes, so that is what is pinned here.

beforeEach(() => setDraftOpen(false));

describe('draftOpen', () => {
  it('reports what was last set', () => {
    expect(isDraftOpen()).toBe(false);
    setDraftOpen(true);
    expect(isDraftOpen()).toBe(true);
  });

  it('tells subscribers each way, with the new value already readable', () => {
    const seen: boolean[] = [];
    onDraftOpenChange(() => seen.push(isDraftOpen()));
    setDraftOpen(true);
    setDraftOpen(false);
    // The order matters: a listener that fired BEFORE the value changed would read "still open"
    // and defer the switch for ever.
    expect(seen).toEqual([true, false]);
  });

  // Without this a re-render that sets the same value would re-fire a deferred switch on every
  // pass, and the switch it defers is not idempotent — it mints a session and navigates.
  it('says nothing when the value has not changed', () => {
    const listener = vi.fn();
    onDraftOpenChange(listener);
    setDraftOpen(false);
    setDraftOpen(false);
    expect(listener).not.toHaveBeenCalled();
  });

  it('stops telling an unsubscribed listener', () => {
    const listener = vi.fn();
    onDraftOpenChange(listener)();
    setDraftOpen(true);
    expect(listener).not.toHaveBeenCalled();
  });
});
