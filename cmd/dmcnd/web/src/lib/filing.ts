// Filing: moving a message to a folder (or back to the Inbox), and sender rules that file a
// sender's new mail on arrival.
//
// The rules and two preferences live in ONE field of the synced settings doc, "swipeFiling",
// which the Apple client reads and writes too. Its shape is shared, so it changes only with the
// other client:
//
//   swipeFiling: {
//     rules: [{ sender, folderId, since }],  // sender lowercased; since in unix SECONDS
//     asksAboutSender: boolean,              // default true
//     fullSwipeArchives: boolean,            // default false
//   }
//
// Fields this client does not know about are kept as they are, in the object and in each rule.

import type { FlagDelta, FlagRecord } from './api/flagStore';
import type { FolderDef } from './api/labelStore';
import { placeOf, type Addressed, type Place, type PlaceContext } from './mailView';

/** A sender's standing rule: their new mail goes straight to a folder. */
export interface FilingRule {
  /** Normalized: trimmed and lowercased. */
  sender: string;
  folderId: string;
  /** Unix seconds. Mail sent before the rule was made is moved when it is made, not by it. */
  since: number;
  [extra: string]: unknown;
}

export interface SwipeFiling {
  rules?: FilingRule[];
  /** Whether filing asks if the sender's other mail, and their new mail, should follow. */
  asksAboutSender?: boolean;
  /** Whether a full swipe to the left archives instead of deleting. */
  fullSwipeArchives?: boolean;
  [extra: string]: unknown;
}

/** What placeOf needs from a message, plus when it was sent (unix seconds). */
export type Fileable = Addressed & { hash: string; subject: string; senderPublicKey: string; sentAt: number };

export function normalizedAddress(a: string): string {
  return a.trim().toLowerCase();
}

/** On unless the owner turned it off. */
export function asksAboutSender(sf: SwipeFiling | undefined): boolean {
  return sf?.asksAboutSender ?? true;
}

/** Off unless the owner chose it. */
export function fullSwipeArchives(sf: SwipeFiling | undefined): boolean {
  return sf?.fullSwipeArchives ?? false;
}

export function rulesOf(sf: SwipeFiling | undefined): FilingRule[] {
  return Array.isArray(sf?.rules) ? sf.rules : [];
}

export function ruleFor(sf: SwipeFiling | undefined, sender: string): FilingRule | undefined {
  const s = normalizedAddress(sender);
  const rules = rulesOf(sf);
  for (let i = rules.length - 1; i >= 0; i--) if (rules[i].sender === s) return rules[i];
  return undefined;
}

/** One rule per sender: a new choice replaces the old one. */
export function withRule(sf: SwipeFiling | undefined, sender: string, folderId: string, nowSec: number): SwipeFiling {
  const s = normalizedAddress(sender);
  return { ...sf, rules: [...rulesOf(sf).filter(r => r.sender !== s), { sender: s, folderId, since: nowSec }] };
}

export function withoutRule(sf: SwipeFiling | undefined, sender: string): SwipeFiling {
  const s = normalizedAddress(sender);
  return { ...sf, rules: rulesOf(sf).filter(r => r.sender !== s) };
}

/** Puts a sender's rule back as it was, for Undo: the earlier rule with its own start time, or none. */
export function restoreRule(sf: SwipeFiling | undefined, before: FilingRule | undefined, sender: string): SwipeFiling {
  const next = withoutRule(sf, sender);
  return before ? { ...next, rules: [...rulesOf(next), before] } : next;
}

/**
 * The rules under their folders, in the folder list's order, senders by address. Rules whose
 * folder was deleted come last, under null: they file nothing until removed.
 */
export function rulesByFolder(sf: SwipeFiling | undefined, folders: FolderDef[]): { folder: FolderDef | null; rules: FilingRule[] }[] {
  const known = new Set(folders.map(f => f.id));
  const sorted = [...rulesOf(sf)].sort((a, b) => a.sender.localeCompare(b.sender));
  const groups: { folder: FolderDef | null; rules: FilingRule[] }[] = [];
  for (const folder of folders) {
    const mine = sorted.filter(r => r.folderId === folder.id);
    if (mine.length) groups.push({ folder, rules: mine });
  }
  const orphans = sorted.filter(r => !known.has(r.folderId));
  if (orphans.length) groups.push({ folder: null, rules: orphans });
  return groups;
}

/**
 * What filing writes: the folder, or none for the Inbox. Back to the Inbox also clears the
 * archived mark, or a message that was filed and archived would land in Archive instead: a folder
 * outranks Archive, so the mark was hidden until the folder went.
 */
export function filingDelta(folderId: string | undefined): FlagDelta {
  return folderId ? { folderId } : { folderId: undefined, archived: undefined };
}

/** Puts back what a move changed, for Undo. */
export function unfilingDelta(before: FlagRecord | undefined): FlagDelta {
  return { folderId: before?.folderId, archived: before?.archived };
}

/**
 * The address filing may follow, or null. `directoryKeyHex` is what the directory publishes for
 * the sender's address (null when the address is not a DMCN identity, as for ordinary email).
 * A verified DMCN sender is followed, and so is ordinary email by its address alone. Never a
 * message claiming a DMCN address while signed by some other key: that is the forgery the row's
 * shield and the reader both refuse.
 *
 * DEV NOTE: as in the Apple client, ordinary email is filed by address alone. Whether it passed
 * SPF/DKIM/DMARC is in the bridge's attestation inside the encrypted body, which the list cannot
 * see, and a directory outage also reads as "not a DMCN identity".
 */
export function filingSender(m: { senderAddress: string; senderPublicKey: string }, directoryKeyHex: string | null): string | null {
  const s = normalizedAddress(m.senderAddress);
  if (!s) return null;
  if (directoryKeyHex && m.senderPublicKey && directoryKeyHex.toLowerCase() !== m.senderPublicKey.toLowerCase()) return null;
  return s;
}

const placeOfFolder = (folderId: string | undefined): Place => (folderId ? `folder:${folderId}` : 'inbox');

/** Where filing can take a message from: the Inbox, a folder or Archive. */
export function canFile(p: Place | null): boolean {
  return p === 'inbox' || p === 'archive' || (p != null && p.startsWith('folder:'));
}

/**
 * The picker's choices for a message: every folder but the one it is in, and the Inbox unless it
 * is already there (from Archive, the Inbox brings it back).
 */
export function filingChoices(here: Place | null, folders: FolderDef[]): { includeInbox: boolean; folders: FolderDef[] } {
  return { includeInbox: here !== 'inbox', folders: folders.filter(f => `folder:${f.id}` !== here) };
}

/**
 * The sender's other mail that filing `m` takes along, to a folder or back to the Inbox
 * (undefined): only what sits where `m` is now. Never Archive, Deleted, Sent, or mail in any other
 * folder or the Inbox when `m` is in a folder. Empty when the sender can't be filed by, or `m`
 * isn't in the Inbox or a folder. `senderOf` is filingSender with the directory's answer applied.
 */
export function sameSenderMail(
  m: Fileable,
  into: string | undefined,
  messages: Fileable[],
  ctx: PlaceContext,
  senderOf: (m: Fileable) => string | null,
): string[] {
  const sender = senderOf(m);
  const from = placeOf(m, ctx);
  if (!sender || !from) return [];
  if (from !== 'inbox' && !from.startsWith('folder:')) return [];
  if (from === placeOfFolder(into)) return [];
  return messages
    .filter(o => o.hash !== m.hash && senderOf(o) === sender && placeOf(o, ctx) === from)
    .map(o => o.hash);
}

/**
 * Inbox mail the rules would file, before the sender check: a message in the Inbox that nobody
 * has touched yet (no flag record: not read, moved or brought back), sent once its sender's rule
 * existed, to a folder that still exists. Filing writes a flag, so each message is filed once and
 * a message the owner moves back stays where they put it. The caller still runs filingSender on
 * each before filing it.
 */
export function autoFilingCandidates(
  messages: Fileable[],
  rules: FilingRule[],
  ctx: PlaceContext,
): { hash: string; folderId: string; message: Fileable }[] {
  if (!rules.length) return [];
  const bySender = new Map<string, FilingRule>();
  for (const r of rules) bySender.set(r.sender, r); // the last one wins, as ruleFor reads it
  const out: { hash: string; folderId: string; message: Fileable }[] = [];
  for (const m of messages) {
    if (ctx.flags.has(m.hash)) continue;
    const rule = bySender.get(normalizedAddress(m.senderAddress));
    if (!rule || !ctx.knownFolderIds.has(rule.folderId) || m.sentAt < rule.since) continue;
    if (placeOf(m, ctx) !== 'inbox') continue;
    out.push({ hash: m.hash, folderId: rule.folderId, message: m });
  }
  return out;
}

/** Moves one item of a list up (-1) or down (+1), for reordering folders and labels. */
export function moved<T>(list: T[], index: number, by: -1 | 1): T[] {
  const to = index + by;
  if (index < 0 || index >= list.length || to < 0 || to >= list.length) return list;
  const next = [...list];
  const [item] = next.splice(index, 1);
  next.splice(to, 0, item);
  return next;
}

/** Moves one item to another index, for dragging. */
export function movedTo<T>(list: T[], from: number, to: number): T[] {
  if (from === to || from < 0 || from >= list.length) return list;
  const clamped = Math.max(0, Math.min(list.length - 1, to));
  const next = [...list];
  const [item] = next.splice(from, 1);
  next.splice(clamped, 0, item);
  return next;
}
