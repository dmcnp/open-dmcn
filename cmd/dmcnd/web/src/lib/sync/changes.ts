// The change feed: what a relay that keeps a change log says has changed in a mailbox and its
// personal store, and how the client asks for it. The transport is the deployment's (the hosted
// product's relays keep a log; the reference daemon's do not), so this module only names the
// shapes the shared client consumes. See useSync.ts.

export type ChangeKind = 'mail_stored' | 'mail_deleted' | 'kv_put' | 'kv_deleted' | 'filter_changed';

export interface ChangeEvent {
  seq: number;
  kind: ChangeKind;
  /** Hex message hash (mail events). */
  hash?: string;
  /** Personal-store key (kv events). */
  key?: string;
  version?: number;
  /** For mail_stored: the message's list entry (base64), when it is still in the mailbox. */
  entry?: string;
}

export interface ChangePage {
  epoch: string;
  events: ChangeEvent[];
  head: number;
  /** The position asked about is not in the relay's log: list everything, continue from head. */
  resync: boolean;
  /** Events past the last one returned remain. */
  more: boolean;
}

/** How far through a relay's change log this device has applied. */
export interface FeedPosition {
  epoch: string;
  seq: number;
}

export interface ChangeFeed {
  /** Events after `after` in the log `epoch` names ('' when the client has no position yet). */
  since(epoch: string, after: number): Promise<ChangePage>;
}

/** The relay keeps no change log (it predates it, or is not configured with one). */
export class ChangeFeedUnavailable extends Error {
  constructor() {
    super('this relay keeps no change log');
    this.name = 'ChangeFeedUnavailable';
  }
}
