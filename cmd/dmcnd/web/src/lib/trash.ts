// Deleted mail: what "deleted" means, in one place.
//
// Deleting a message does not remove it. It marks it — `trashedAt` on its flag record, sealed to
// the owner in personal storage like every other flag — and the message itself stays exactly where
// it was: a received message in the mailbox, sealed to this account's key; a sent one in personal
// storage, sealed the same way. Nothing is decrypted to be kept and nothing is copied, so mail
// waiting in Deleted is held exactly as it was held before. Restoring clears the mark, and the
// message is back wherever its other flags put it (a folder, the archive, a label).
//
// Removal for good is the client's job, because only the owner can read the mark: the relay holds
// the flag as ciphertext and has no idea which messages are waiting or since when. So the sweep
// runs whenever an unlocked client is open (hooks/useTrashPurge.ts), and mail whose time is up
// while no client is open goes the next time one is.
//
// How long a message has waited is counted from when the RELAY recorded the mark, not from the
// `trashedAt` inside it. A device can be allowed to file mail without the account's signing key
// (SPEC_EXT_DEVICES.md §3), and such a device writes flag records. If the sweep trusted the time
// in the record, that device could backdate it and have the owner's own client delete the mail
// for it, which is the one thing it was not allowed to do. `trashedAt` is what the Deleted view
// shows and sorts by. Any later change to the same record (marking it read, say) moves the
// relay's time forward and so lengthens the wait, which errs on the side of keeping mail.

import type { FlagRecord } from './api/flagStore';
import type { FilterList } from './api/filterList';
import { filterBlocks } from './trust/category';

export const TRASH_DAYS_DEFAULT = 7;
export const TRASH_DAYS_MIN = 1;
export const TRASH_DAYS_MAX = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

/** The retention the account asked for, as whole days within the range offered. */
export function trashDays(setting: number | undefined): number {
  if (setting === undefined || !Number.isFinite(setting)) return TRASH_DAYS_DEFAULT;
  return Math.min(TRASH_DAYS_MAX, Math.max(TRASH_DAYS_MIN, Math.round(setting)));
}

/** When a message deleted at `trashedAt` is removed for good, unix ms. */
export function purgeAt(trashedAt: number, days: number): number {
  return trashedAt + days * DAY_MS;
}

/**
 * The messages whose time in Deleted is up, by hash. The retention is read now rather than when
 * each was deleted, so changing it applies to everything already waiting.
 *
 * `storedAt` is when each record was last written by a clock its writer did not choose (unix ms;
 * useFlags). The wait is counted from that. A record with no entry there was written before
 * relays kept the time, when only a device holding the account's signing key could write one, so
 * for those the time in the record is still the owner's word and is used.
 */
export function expiredTrash(flags: Map<string, FlagRecord>, days: number, now: number, storedAt: Map<string, number> = new Map()): string[] {
  const out: string[] = [];
  for (const [hash, f] of flags) {
    if (f.trashedAt === undefined) continue;
    if (purgeAt(storedAt.get(hash) ?? f.trashedAt, days) <= now) out.push(hash);
  }
  return out;
}

/**
 * Whether a message shows in Deleted: it was deleted, and it is not something the owner never
 * sees anywhere else either — a control message, or mail from a blocked sender. Those are still
 * removed on schedule; they are just not listed. The rail and the view both ask this, so the
 * Deleted row is never there for an empty view.
 */
export function shownInDeleted(
  m: { hash: string; subject: string; senderAddress: string; senderPublicKey: string },
  address: string | null,
  flags: Map<string, FlagRecord>,
  filter: FilterList | null,
  control: Set<string>,
): boolean {
  if (flags.get(m.hash)?.trashedAt === undefined || control.has(m.subject)) return false;
  const self = address != null && m.senderAddress.toLowerCase() === address.toLowerCase();
  return self || !filterBlocks(filter, m.senderAddress, m.senderPublicKey);
}

/** "today", "tomorrow", "in 3 days": when a message in Deleted goes, counted in calendar days. */
export function purgeWhen(trashedAt: number, days: number, now: number): string {
  const at = new Date(purgeAt(trashedAt, days));
  const today = new Date(now);
  const midnight = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const n = Math.round((midnight(at) - midnight(today)) / DAY_MS);
  if (n <= 0) return 'today';
  if (n === 1) return 'tomorrow';
  return `in ${n} days`;
}
