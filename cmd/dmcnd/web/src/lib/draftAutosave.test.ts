import { describe, it, expect } from 'vitest';
import { SaveScheduler, type Timers } from './draftAutosave';

// A clock the test moves by hand.
function fakeTimers() {
  let now = 0;
  let next = 0;
  const due = new Map<number, { at: number; fn: () => void }>();
  const timers: Timers = {
    set: (fn, ms) => { const id = ++next; due.set(id, { at: now + ms, fn }); return id; },
    clear: id => { due.delete(id as number); },
    now: () => now,
  };
  const advance = async (ms: number) => {
    const until = now + ms;
    for (;;) {
      const [id, t] = [...due.entries()].filter(([, t]) => t.at <= until).sort((a, b) => a[1].at - b[1].at)[0] ?? [];
      if (!t) break;
      now = t.at;
      due.delete(id!);
      t.fn();
      await Promise.resolve();
      await Promise.resolve();
    }
    now = until;
  };
  return { timers, advance };
}

describe('SaveScheduler', () => {
  it('saves once typing pauses, not per change', async () => {
    const { timers, advance } = fakeTimers();
    let saves = 0;
    const s = new SaveScheduler(async () => { saves++; }, 3000, 15000, timers);
    for (let i = 0; i < 5; i++) { s.touch(); await advance(1000); }
    expect(saves).toBe(0);
    await advance(3000);
    expect(saves).toBe(1);
    expect(s.pending).toBe(false);
  });

  it('saves at the ceiling while changes keep coming', async () => {
    const { timers, advance } = fakeTimers();
    let saves = 0;
    const s = new SaveScheduler(async () => { saves++; }, 3000, 15000, timers);
    for (let i = 0; i < 16; i++) { s.touch(); await advance(1000); }
    expect(saves).toBe(1);
  });

  it('flush saves what is pending, and nothing when nothing is', async () => {
    const { timers } = fakeTimers();
    let saves = 0;
    const s = new SaveScheduler(async () => { saves++; }, 3000, 15000, timers);
    await s.flush();
    expect(saves).toBe(0);
    s.touch();
    await s.flush();
    expect(saves).toBe(1);
  });

  it('a change during a save is saved by the next one, never concurrently', async () => {
    const { timers } = fakeTimers();
    let inFlight = 0;
    let maxInFlight = 0;
    let saves = 0;
    let release: () => void = () => undefined;
    const s = new SaveScheduler(async () => {
      inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise<void>(r => { release = r; });
      inFlight--; saves++;
    }, 3000, 15000, timers);
    s.touch();
    const first = s.flush();
    s.touch();
    const second = s.flush();
    release();
    await first;
    await Promise.resolve();
    release();
    await second;
    expect(saves).toBe(2);
    expect(maxInFlight).toBe(1);
  });

  it('a failed save stays pending and is retried', async () => {
    const { timers, advance } = fakeTimers();
    let attempts = 0;
    const s = new SaveScheduler(async () => { if (++attempts === 1) throw new Error('offline'); }, 3000, 15000, timers);
    s.touch();
    await expect(s.flush()).rejects.toThrow('offline');
    expect(s.pending).toBe(true);
    await advance(15000);
    expect(attempts).toBe(2);
    expect(s.pending).toBe(false);
  });

  it('abandon drops what is pending and waits for a save in flight', async () => {
    const { timers, advance } = fakeTimers();
    let saves = 0;
    let release: () => void = () => undefined;
    const s = new SaveScheduler(async () => { await new Promise<void>(r => { release = r; }); saves++; }, 3000, 15000, timers);
    s.touch();
    const inFlight = s.flush();
    s.touch();
    let abandoned = false;
    const done = s.abandon().then(() => { abandoned = true; });
    await Promise.resolve();
    expect(abandoned).toBe(false);
    release();
    await inFlight;
    await done;
    await advance(20000);
    expect(saves).toBe(1);
    expect(s.pending).toBe(false);
  });
});
