// One pass of the change feed over the mail list: ask the relay what changed since the position
// these rows are at, apply it, and only then move the position. Pure of React, so it can be
// driven in a test against a stub feed and a real MailboxSync.

import type { ChangeEvent, ChangeFeed, FeedPosition } from './changes';

/** The part of MailboxSync a feed pass drives. */
export interface FeedTarget {
  list(): Promise<unknown>;
  applyEvents(events: ChangeEvent[]): Promise<void>;
  feedPosition(): Promise<FeedPosition | null>;
  setFeedPosition(p: FeedPosition): Promise<void>;
  invalidateRing(): void;
}

/** What a pass tells everyone else who keeps a copy of something the feed covers. */
export interface ChangeBatch {
  events: ChangeEvent[];
  /** The position was not in the relay's log: everything may have changed. */
  resync: boolean;
}

// A feed that keeps saying "more" is still bounded per pass; the next poll carries on.
const MAX_PAGES = 50;

export async function feedPass(feed: ChangeFeed, target: FeedTarget, publish: (b: ChangeBatch) => void): Promise<void> {
  const kept = await target.feedPosition();
  let pos: FeedPosition = kept ? { ...kept } : { epoch: '', seq: 0 };
  for (let page = 0; page < MAX_PAGES; page++) {
    const res = await feed.since(pos.epoch, pos.seq);
    if (res.resync) {
      // The head was read before the listing starts, so anything that lands during it is both
      // in the listing and after the head: replayed next pass, harmlessly.
      const next = { epoch: res.epoch, seq: res.head };
      await target.list();
      await target.setFeedPosition(next);
      publish({ events: [], resync: true });
      return;
    }
    if (res.events.length === 0) return;
    // The account's aliases changed: mail sealed to a new one needs the ring rebuilt to open.
    if (res.events.some(e => e.key === 'aliases/isolated')) target.invalidateRing();
    await target.applyEvents(res.events);
    pos = { epoch: res.epoch, seq: res.events[res.events.length - 1].seq };
    await target.setFeedPosition(pos);
    publish({ events: res.events, resync: false });
    if (!res.more) return;
  }
}
