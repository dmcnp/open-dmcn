// What "unread" means, in one place.
//
// The shell's inbox badge and the account switcher's per-account counts have to
// agree — a badge that says 3 and a menu that says 5 for the same mailbox is worse
// than no count at all. Both call countUnread, so the rule can only change once.

import type { Preview } from './api/mailboxRest';
import type { FlagRecord } from './api/flagStore';
import type { FilterList } from './api/filterRest';
import { isReceivedForMe } from './mailView';
import { filterBlocks } from './trust/category';
import { deployment } from '../deployment';

// Control messages this deployment carries surface in their own panels, not the inbox, so
// they never count as unread mail. A function rather than a module-level Set: `deployment`
// imports screens that reach this module, and a value read during module evaluation would
// depend on which side of that cycle ran first.
//
// This is the ONE definition. InboxMain and AppLayout had each grown their own copy of the
// same set, which is how a subject ends up filtered out of one list and not another.
export const controlSubjects = () => new Set<string>(deployment.controlSubjects);

// countUnread counts received, non-control, non-archived, unread mail, excluding
// blocked senders. Trust is decided at read time rather than by list placement, so
// pending (unknown) senders DO count — only the personal blocklist suppresses.
// Mail from the account to itself is inherently trusted and always counts.
export function countUnread(
  previews: Preview[],
  address: string | null,
  flags: Map<string, FlagRecord>,
  filter: FilterList | null,
): number {
  let n = 0;
  for (const m of previews) {
    if (!isReceivedForMe(m, address)) continue;
    if (controlSubjects().has(m.subject)) continue;
    const f = flags.get(m.hash);
    if (f?.archived || f?.read) continue;
    const self = address != null && m.senderAddress.toLowerCase() === address.toLowerCase();
    if (!self && filterBlocks(filter, m.senderAddress, m.senderPublicKey)) continue;
    n++;
  }
  return n;
}
