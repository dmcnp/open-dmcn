// The steps behind a move, a delete or an archive with Undo, apart from React so tests can drive
// them with a fake flag store: what is written, what the bar says, what Undo puts back, and what
// happens when a write fails or the account changes before Undo is pressed.

import type { FlagDelta, FlagRecord } from './api/flagStore';
import { filingDelta, unfilingDelta } from './filing';

export interface ActionDeps {
  /** Writes one message's flag change; rejects when the write fails. */
  setFlag: (hash: string, delta: FlagDelta) => Promise<void>;
  /** The message's flag record as this tab knows it now. */
  flagOf: (hash: string) => FlagRecord | undefined;
  /** Shows the bar: with `undo`, an Undo button; without, a plain notice. */
  notify: (text: string, undo?: () => Promise<void>) => void;
  /** The signed-in account now. Undo does nothing once it has changed. */
  account: () => string | null;
}

export interface Done {
  /** The messages whose write succeeded. */
  done: string[];
  /** Puts them back; undefined when nothing was done. */
  undo?: () => Promise<void>;
}

/** Thrown by an Undo whose writes failed, so the bar can say so. */
export class UndoFailedError extends Error {
  constructor() { super("Couldn't undo. Check your connection and try again."); this.name = 'UndoFailedError'; }
}

const failedText = (n: number, what: string) =>
  `Couldn't ${what} ${n > 1 ? 'these messages' : 'this message'}. Check your connection and try again.`;

// changeWithUndo writes `delta` to each message and offers Undo for the ones that took. `back`
// says, from a message's record before the change, what puts it back. `afterUndo` runs once the
// messages are back (an "always" move restores the sender's rule there).
async function changeWithUndo(
  deps: ActionDeps,
  hashes: string[],
  delta: FlagDelta,
  back: (before: FlagRecord | undefined) => FlagDelta,
  text: { all: (n: number) => string; some: (done: number, of: number) => string; verb: string },
  afterUndo?: () => Promise<void>,
): Promise<Done> {
  const account = deps.account();
  const before = new Map(hashes.map(h => [h, deps.flagOf(h)]));
  const results = await Promise.allSettled(hashes.map(h => deps.setFlag(h, delta)));
  const done = hashes.filter((_, i) => results[i].status === 'fulfilled');
  if (done.length === 0) {
    deps.notify(failedText(hashes.length, text.verb));
    return { done };
  }
  const undo = async () => {
    // Pressed after switching account, locking or signing out: these messages are not in the
    // mailbox the store now writes to, so nothing is written.
    if (deps.account() !== account) return;
    const res = await Promise.allSettled(done.map(h => deps.setFlag(h, back(before.get(h)))));
    if (afterUndo) await afterUndo();
    if (res.some(r => r.status === 'rejected')) throw new UndoFailedError();
  };
  deps.notify(done.length < hashes.length ? text.some(done.length, hashes.length) : text.all(done.length), undo);
  return { done, undo };
}

/** Moves to a folder, or to the Inbox with undefined, with Undo. `place` names where they went. */
export function moveWithUndo(
  deps: ActionDeps,
  hashes: string[],
  folderId: string | undefined,
  place: string,
  afterUndo?: () => Promise<void>,
): Promise<Done> {
  return changeWithUndo(deps, hashes, filingDelta(folderId), unfilingDelta, {
    all: n => (n > 1 ? `Moved ${n} messages to ${place}` : `Moved to ${place}`),
    some: (d, of) => `Moved ${d} of ${of} messages to ${place}. The rest couldn't be moved.`,
    verb: 'move',
  }, afterUndo);
}

/** Moves to Deleted, with Undo. */
export function trashWithUndo(deps: ActionDeps, hashes: string[], now: number): Promise<Done> {
  return changeWithUndo(deps, hashes, { trashedAt: now }, f => ({ trashedAt: f?.trashedAt }), {
    all: () => 'Moved to Deleted',
    some: (d, of) => `Moved ${d} of ${of} messages to Deleted. The rest couldn't be moved.`,
    verb: 'delete',
  });
}

/** Archives, or brings back from Archive, with Undo. */
export function setArchivedWithUndo(deps: ActionDeps, hashes: string[], archived: boolean): Promise<Done> {
  return changeWithUndo(deps, hashes, { archived }, f => ({ archived: f?.archived }), {
    all: () => (archived ? 'Archived' : 'Moved out of Archive'),
    some: (d, of) => `${archived ? 'Archived' : 'Moved out of Archive'} ${d} of ${of} messages. The rest couldn't be changed.`,
    verb: archived ? 'archive' : 'unarchive',
  });
}

/**
 * "Always": moves the message and the sender's other mail, then saves the rule. The rule is saved
 * only once something moved, and Undo waits for that save to finish before putting the earlier
 * rule back: otherwise an Undo pressed straight away could land first and the save re-add the
 * rule afterwards.
 */
export async function moveAlwaysWithUndo(
  deps: ActionDeps,
  hashes: string[],
  folderId: string | undefined,
  place: string,
  saveRule: () => Promise<void>,
  restoreRule: () => Promise<void>,
): Promise<Done> {
  let saved: Promise<void> = Promise.resolve();
  const moved = await moveWithUndo(deps, hashes, folderId, place, async () => {
    await saved.catch(() => { /* nothing was saved, so nothing to put back past this */ });
    await restoreRule();
  });
  if (!moved.undo) return moved;
  saved = saveRule();
  try {
    await saved;
  } catch {
    deps.notify(
      folderId
        ? `Moved, but new mail from this sender won't go to ${place} automatically: the rule couldn't be saved.`
        : `Moved, but the sender's rule couldn't be removed.`,
      moved.undo,
    );
  }
  return moved;
}
