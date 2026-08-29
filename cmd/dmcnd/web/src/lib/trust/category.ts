// Client-side sender categorization for the pending-queue model (§14.2). A received
// message is allowlisted (its sender carries a trust provenance and its key still
// matches what we pinned), blocked (the sender's key/address is on the personal
// blocklist), or pending (valid but unknown — the default). This is a pure,
// synchronous decision over locally-held data (contacts + the mail filter); it does
// NOT hit the directory, so it can classify the whole inbox without per-row awaits.

import { fromBase64, toHex } from '../crypto/keys';
import type { ContactRecord } from '../api/contactStore';
import type { FilterList } from '../api/filterList';

export type SenderCategory = 'allowlisted' | 'pending' | 'blocked';

function domainOf(addr: string): string {
  const a = addr.trim().toLowerCase();
  const i = a.lastIndexOf('@');
  return i >= 0 ? a.slice(i + 1) : a;
}

// hexOfB64 converts a base64 key to lowercase hex (empty on malformed input).
function hexOfB64(b64: string): string {
  try {
    return toHex(fromBase64(b64));
  } catch {
    return '';
  }
}

// filterBlocks mirrors the relay's key-bound personal blocklist: a sender_keys
// match ALWAYS blocks (unconditional, §14.3.1), and — only in deny mode — an
// address/domain match blocks too. (Allow-mode address lists are an admission
// policy, not a per-sender block, so they don't mark a received message "blocked".)
export function filterBlocks(filter: FilterList | null, senderAddress: string, senderKeyHex: string): boolean {
  if (!filter) return false;
  const keyHex = senderKeyHex.toLowerCase();
  if (keyHex && (filter.sender_keys ?? []).some(k => k.toLowerCase() === keyHex)) return true;
  if ((filter.mode ?? 'deny') !== 'deny') return false;
  const addr = senderAddress.trim().toLowerCase();
  if ((filter.senders ?? []).some(s => s.trim().toLowerCase() === addr)) return true;
  const dom = domainOf(senderAddress);
  return (filter.domains ?? []).some(d => d.trim().toLowerCase() === dom);
}

// categorizeSender returns the pending-queue category for a received message. Note
// a key change on an allowlisted contact demotes them back to pending (re-verify),
// matching the reader's key_changed danger verdict.
export function categorizeSender(
  senderAddress: string,
  senderKeyHex: string,
  contact: ContactRecord | undefined,
  filter: FilterList | null,
): SenderCategory {
  if (filterBlocks(filter, senderAddress, senderKeyHex)) return 'blocked';
  // Any contact is an allowlist entry (contacts ARE the allowlist); provenance only
  // labels its strength. A pinned-key change demotes back to pending (re-verify).
  if (contact) {
    if (contact.ed25519Pub && hexOfB64(contact.ed25519Pub) !== senderKeyHex.toLowerCase()) return 'pending';
    return 'allowlisted';
  }
  return 'pending';
}
