// The account's block/allow list — its shape, and what a client must be able to do with it.
//
// WHERE the list lives is a deployment decision with a real consequence, so it is a seam
// (lib/deployment.ts) rather than a detail. Held at the mailbox relay, sealed to the owner
// AND the relay, the relay can silently DROP a blocked sender at delivery — the block is
// enforced before the mail is ever stored. Held in the browser it is advisory: it drives the
// client-side trust view, and blocked mail still arrives, it just isn't shown.
//
// Both are honest positions, and the type is the same either way, so consumers
// (useMailFilter, BlockedSenders) never need to know which one they have.

import type { WorkingKeys } from '../crypto/workingKeys';

// FilterList mirrors Go's mailfilter.List JSON.
export interface FilterList {
  mode: 'deny' | 'allow';
  domains: string[];
  senders: string[];
  allow_verified?: boolean;
  // Hex ed25519 public keys of blocked identities (§14.3.1). Unlike senders/domains,
  // a sender_keys match ALWAYS applies regardless of mode — a personal blocklist bound
  // to the cryptographic identity, so a blocked sender can't evade by changing their
  // address string.
  sender_keys?: string[];
}

export function emptyFilterList(): FilterList {
  return { mode: 'deny', domains: [], senders: [], allow_verified: false, sender_keys: [] };
}

// MailFilter is the whole interface a consumer needs. get() returns null when the account
// has no list yet, which is distinct from an empty one.
export interface MailFilter {
  get(): Promise<FilterList | null>;
  save(list: FilterList): Promise<void>;
  clear(): Promise<void>;
}

// MailFilterFactory builds one for an account. explicitToken names a session that isn't the
// tab's current account (a background read); absent ⇒ the global session.
export type MailFilterFactory = (keys: WorkingKeys, explicitToken?: string) => MailFilter;
