import { describe, expect, it } from 'vitest';
import type { ChangeEvent, ChangeFeed, ChangePage, FeedPosition } from './changes';
import { feedPass, type ChangeBatch, type FeedTarget } from './feedSync';

// What the pass did, in order, so a test can check that the position only ever moves after the
// change it covers has been applied.
function target(kept: FeedPosition | null) {
  const log: string[] = [];
  let pos = kept;
  const t: FeedTarget = {
    list: async () => { log.push('list'); },
    applyEvents: async (e: ChangeEvent[]) => { log.push(`apply ${e.map(x => x.seq).join(',')}`); },
    feedPosition: async () => pos,
    setFeedPosition: async p => { pos = p; log.push(`position ${p.epoch}:${p.seq}`); },
    invalidateRing: () => { log.push('ring'); },
  };
  return { t, log, position: () => pos };
}

function feed(pages: ChangePage[]) {
  const asked: Array<[string, number]> = [];
  const f: ChangeFeed = {
    since: async (epoch, after) => { asked.push([epoch, after]); return pages.shift()!; },
  };
  return { f, asked };
}

const page = (over: Partial<ChangePage>): ChangePage => ({ epoch: 'e1', events: [], head: 0, resync: false, more: false, ...over });
const ev = (seq: number, kind: ChangeEvent['kind'] = 'kv_put', key = 'flags/x'): ChangeEvent => ({ seq, kind, key });

describe('feedPass', () => {
  it('lists once and starts from the head when the relay says resync', async () => {
    const { t, log, position } = target(null);
    const { f, asked } = feed([page({ resync: true, head: 17 })]);
    const batches: ChangeBatch[] = [];
    await feedPass(f, t, b => batches.push(b));
    expect(asked).toEqual([['', 0]]);
    expect(log).toEqual(['list', 'position e1:17']);
    expect(position()).toEqual({ epoch: 'e1', seq: 17 });
    expect(batches).toEqual([{ events: [], resync: true }]);
  });

  it('applies events, then moves the position past them, then tells everyone', async () => {
    const { t, log } = target({ epoch: 'e1', seq: 3 });
    const { f, asked } = feed([page({ events: [ev(4), ev(5)], head: 5 })]);
    const batches: ChangeBatch[] = [];
    await feedPass(f, t, b => { log.push('publish'); batches.push(b); });
    expect(asked).toEqual([['e1', 3]]);
    expect(log).toEqual(['apply 4,5', 'position e1:5', 'publish']);
    expect(batches[0].events.map(e => e.seq)).toEqual([4, 5]);
  });

  it('keeps asking while the relay says there is more', async () => {
    const { t, position } = target({ epoch: 'e1', seq: 0 });
    const { f, asked } = feed([page({ events: [ev(1)], more: true }), page({ events: [ev(2)] })]);
    await feedPass(f, t, () => {});
    expect(asked).toEqual([['e1', 0], ['e1', 1]]);
    expect(position()).toEqual({ epoch: 'e1', seq: 2 });
  });

  it('does not move the position when applying fails', async () => {
    const { t, position } = target({ epoch: 'e1', seq: 3 });
    t.applyEvents = async () => { throw new Error('boom'); };
    const { f } = feed([page({ events: [ev(4)] })]);
    await expect(feedPass(f, t, () => {})).rejects.toThrow('boom');
    expect(position()).toEqual({ epoch: 'e1', seq: 3 });
  });

  it('rebuilds the decrypt ring when the account’s aliases change', async () => {
    const { t, log } = target({ epoch: 'e1', seq: 0 });
    const { f } = feed([page({ events: [ev(1, 'kv_put', 'aliases/isolated')] })]);
    await feedPass(f, t, () => {});
    expect(log[0]).toBe('ring');
  });

  it('does nothing when nothing changed', async () => {
    const { t, log } = target({ epoch: 'e1', seq: 9 });
    const { f } = feed([page({ head: 9 })]);
    await feedPass(f, t, () => {});
    expect(log).toEqual([]);
  });
});
