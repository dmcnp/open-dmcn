import { describe, expect, it } from 'vitest';
import { Backfiller, FAILURE_STREAK, FLUSH_EVERY, MAX_FAILURES, planPass, type IndexLike } from './backfill';

describe('planPass', () => {
  const c = (hash: string, sentAt: number, blocked = false) => ({ hash, sentAt, blocked });

  it('fetches what is missing, newest first, and never a blocked sender', () => {
    const plan = planPass([c('old', 1), c('new', 3), c('mid', 2), c('spam', 4, true)], h => h === 'mid');
    expect(plan.fetch).toEqual(['new', 'old']);
    expect(plan.remove).toEqual([]);
  });

  it('removes only against a complete list', () => {
    const cands = [c('kept', 1), c('now-blocked', 2, true)];
    expect(planPass(cands, () => true).remove).toEqual([]);
    expect(planPass(cands, () => true, ['kept', 'now-blocked', 'deleted']).remove).toEqual(['now-blocked', 'deleted']);
  });
});

class FakeIndex implements IndexLike {
  docs = new Map<string, string>();
  unflushed = 0;
  flushes = 0;
  compactions = 0;
  wantsCompaction = false;
  has(h: string) { return this.docs.has(h); }
  hashes() { return this.docs.keys(); }
  async add(h: string, text: string) { this.docs.set(h, text); this.unflushed++; }
  async remove(hs: Iterable<string>) { for (const h of hs) this.docs.delete(h); this.unflushed++; }
  async flush() { if (this.unflushed) this.flushes++; this.unflushed = 0; }
  get pending() { return this.unflushed > 0; }
  async compact() { this.compactions++; this.wantsCompaction = false; }
}

function setup(opts: { fail?: (h: string) => boolean; runnable?: () => boolean } = {}) {
  const index = new FakeIndex();
  const fetched: string[] = [];
  let retry: number | null = null;
  const b = new Backfiller({
    index,
    fetch: async h => {
      fetched.push(h);
      if (opts.fail?.(h)) throw new Error('boom');
      return { text: `body of ${h}`, filenames: [] };
    },
    runnable: opts.runnable ?? (() => true),
    onProgress: () => {},
    retryLater: ms => { retry = ms; },
  });
  return { b, index, fetched, retry: () => retry };
}

const cands = (n: number) => Array.from({ length: n }, (_, i) => ({ hash: `h${i}`, sentAt: i, blocked: false }));

describe('Backfiller', () => {
  it('indexes everything missing and writes it out', async () => {
    const { b, index } = setup();
    b.update(cands(5), true);
    await b.settled();
    expect(index.docs.size).toBe(5);
    expect(index.pending).toBe(false);
  });

  it('writes every FLUSH_EVERY messages, so a closed tab loses little', async () => {
    const { b, index } = setup();
    b.update(cands(FLUSH_EVERY * 2 + 10), true);
    await b.settled();
    expect(index.flushes).toBe(3);
  });

  it('does nothing while not runnable, and resumes on a kick', async () => {
    let on = false;
    const { b, index } = setup({ runnable: () => on });
    b.update(cands(3), true);
    await b.settled();
    expect(index.docs.size).toBe(0);
    on = true;
    b.kick();
    await b.settled();
    expect(index.docs.size).toBe(3);
  });

  it('gives up on a message after MAX_FAILURES passes', async () => {
    const { b, index, fetched } = setup({ fail: h => h === 'h1' });
    for (let i = 0; i < MAX_FAILURES + 2; i++) { b.update(cands(3), true); await b.settled(); }
    expect(fetched.filter(h => h === 'h1').length).toBe(MAX_FAILURES);
    expect(index.docs.size).toBe(2);
  });

  it('ends a pass on a failure streak and asks to be retried', async () => {
    const { b, fetched, retry } = setup({ fail: () => true });
    b.update(cands(50), true);
    await b.settled();
    expect(fetched.length).toBeLessThan(FAILURE_STREAK + 2);
    expect(retry()).not.toBeNull();
  });

  it('re-plans when new mail arrives mid-pass, so it is indexed next', async () => {
    const { b, fetched } = setup();
    b.update(cands(10), true);
    b.update([...cands(10), { hash: 'fresh', sentAt: 999, blocked: false }], true);
    await b.settled();
    expect(fetched).toContain('fresh');
    expect(fetched.indexOf('fresh')).toBeLessThan(fetched.length - 1);
  });

  it('removes messages that left the mailbox', async () => {
    const { b, index } = setup();
    b.update(cands(3), true);
    await b.settled();
    b.update(cands(2), true);
    await b.settled();
    expect([...index.docs.keys()].sort()).toEqual(['h0', 'h1']);
  });

  it('compacts after a pass when the index asks', async () => {
    const { b, index } = setup();
    index.wantsCompaction = true;
    b.update(cands(1), true);
    await b.settled();
    expect(index.compactions).toBe(1);
  });

  it('stops and writes what it has', async () => {
    const { b, index } = setup();
    b.update(cands(3), true);
    await b.stop();
    expect(index.pending).toBe(false);
    b.update(cands(10), true);
    await b.settled();
    expect(index.docs.size).toBeLessThanOrEqual(3);
  });
});
