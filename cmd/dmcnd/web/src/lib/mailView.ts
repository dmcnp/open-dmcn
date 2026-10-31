// Sent-vs-received classification for mailbox messages.
//
// Mailbox messages are per-recipient copies. Normally a copy in my mailbox was sent
// by someone else, so it's received mail. The one exception is mailing yourself: the
// single copy that lands in my mailbox has ME as both sender and recipient. That copy
// is genuine received mail and belongs in the Inbox — it also appears in Sent, which
// reads from the separate personal-store record (a different source, so no duplicate).
//
// isReceivedForMe centralizes the rule both the received views (InboxMain) and the
// nav counts (AppLayout) key off, so they never disagree about whether a self-
// addressed message is shown/counted.

import type { FlagRecord } from './api/flagStore';
import type { FilterList } from './api/filterList';
import { isSentStoreHash } from './api/sentStore';
import { filterBlocks } from './trust/category';
import { shownInDeleted } from './trash';

export interface Addressed {
  senderAddress: string;
  recipientAddress: string;
  to: string[];
  cc: string[];
}

// isReceivedForMe reports whether a mailbox message should appear in received views
// (Inbox/Pending/labels/folders) for the owner at `address`.
export function isReceivedForMe(m: Addressed, address: string | null): boolean {
  if (!address) return false;
  const me = address.toLowerCase();
  if (m.senderAddress.toLowerCase() !== me) return true; // from someone else → received
  // I sent it — received only if I'm also a recipient (I mailed myself).
  return m.recipientAddress.toLowerCase() === me
    || m.to.some(a => a.toLowerCase() === me)
    || m.cc.some(a => a.toLowerCase() === me);
}

/** Where a message is listed: a system view, or a user folder ("folder:<id>"). */
export type Place = 'inbox' | 'archive' | 'sent' | 'deleted' | `folder:${string}`;

export interface PlaceContext {
  address: string | null;
  flags: Map<string, FlagRecord>;
  filter: FilterList | null;
  control: Set<string>;
  /** Folders that still exist: a message filed in a deleted folder is back in the Inbox. */
  knownFolderIds: Set<string>;
}

// placeOf says where a message lives, for search, which lists mail from every view at once and
// keeps each row's actions (Archive or Unarchive, Restore, the Sent layout) and its location tag
// true to that place. null for what search leaves out, which is what the index leaves out too:
// control messages, and mail from a blocked sender (in Deleted as well, as shownInDeleted says).
//
// Deleted wins over everything, since deleted mail is listed nowhere else. A message both filed
// and archived appears in the folder and in Archive; its place is the folder, the more specific.
export function placeOf(
  m: Addressed & { hash: string; subject: string; senderPublicKey: string },
  ctx: PlaceContext,
): Place | null {
  const f = ctx.flags.get(m.hash);
  if (f?.trashedAt !== undefined) {
    return shownInDeleted(m, ctx.address, ctx.flags, ctx.filter, ctx.control) ? 'deleted' : null;
  }
  if (ctx.control.has(m.subject)) return null;
  if (isSentStoreHash(m.hash) || !isReceivedForMe(m, ctx.address)) return 'sent';
  const self = ctx.address != null && m.senderAddress.toLowerCase() === ctx.address.toLowerCase();
  if (!self && filterBlocks(ctx.filter, m.senderAddress, m.senderPublicKey)) return null;
  if (f?.folderId && ctx.knownFolderIds.has(f.folderId)) return `folder:${f.folderId}`;
  if (f?.archived) return 'archive';
  return 'inbox';
}

// previewText renders a message's snippet for a one-line list row.
//
// The snippet is a SIGNED header field — the first bytes of the body, fixed at the moment the
// message was sealed — so nothing here can change what it contains, only how it reads. That
// matters for bridged mail: an HTML-only newsletter is converted to text at the bridge, and
// the first 140 bytes of that conversion are usually navigation chrome carrying reference
// markers, which arrive as "[image: Reddit][1] [merten-dmcn][1] [r/GMail][2]".
//
// So this is presentation only: unwrap "[label][n]" to its label, drop image placeholders
// entirely (an inbox row has no room to describe pictures), and flatten the whole thing to one
// line. What it deliberately does NOT do is try to find "the interesting part" — the body is
// not here to look in, and guessing which fragment matters would be inventing a preview rather
// than showing one.
export function previewText(snippet: string): string {
  return snippet
    // "[image: alt]" carries no text worth a row; it goes before the link unwrapping so an
    // image that was also a link ("[image: alt][2]") leaves nothing behind.
    .replace(/\[image:[^\]]*\]\s*(\[\d+\])?/g, '')
    // "[label][n]" → "label". The reference number is meaningless without the table, which
    // lives at the end of the body and is not in the snippet.
    .replace(/\[([^\]]*)\]\[\d+\]/g, '$1')
    // A bare "[n]" is a link whose text was empty — nothing to show.
    .replace(/\[\d+\]/g, '')
    // The snippet is a byte-truncated prefix of the body, so it routinely ends in the middle
    // of a construct. A half-written image placeholder is dropped; any other unclosed bracket
    // keeps its text and loses the bracket, since that text is the start of a real sentence.
    .replace(/\[image:[^\]]*$/, '')
    .replace(/\[([^\]]*)$/, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

// recipientsOf lists everyone a message went to (To + Cc), falling back to the single
// recipientAddress for the pre-feature copies that carry no lists. A Sent row is "about"
// the first of them, so the row's label and its shield can never disagree about who that is.
export function recipientsOf(m: Addressed): string[] {
  return m.to.length || m.cc.length ? [...m.to, ...m.cc] : [m.recipientAddress];
}
