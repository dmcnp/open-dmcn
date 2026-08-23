// How a correspondent is reachable — the one bit worth a glance per row: is this
// person a DMCN identity (mail between you is sealed key-to-key), or a legacy email
// address reached over a bridge (which can never be end-to-end encrypted)? This is
// deliberately NOT a trust verdict: senderTrust.ts answers "should I believe this
// sender?" and the reader shows that in full. Here we only say which network the
// counterparty lives on.

import { fromBase64, toHex } from '../crypto/keys';
import type { ContactRecord } from '../api/contactStore';
import type { IdentityLookupResponse } from '../api/client';

export type SenderKind = 'dmcn' | 'legacy' | 'unknown';

// contactKind classifies from locally-held data alone — no network. A contact we
// resolved in the directory carries a fingerprint (and usually a pinned key); a
// contact with neither was allowlisted as a bare address, which is what a legacy
// (bridged) correspondent looks like.
export function contactKind(rec: ContactRecord | undefined): SenderKind {
  if (!rec) return 'unknown';
  return rec.fingerprint || rec.ed25519Pub ? 'dmcn' : 'legacy';
}

// hexOfB64 converts a base64 key to lowercase hex (empty on malformed input).
function hexOfB64(b64: string | undefined): string {
  if (!b64) return '';
  try {
    return toHex(fromBase64(b64));
  } catch {
    return '';
  }
}

// The directory answer per address, shared by every row that mentions it and kept
// for the session: a mail list re-renders constantly and would otherwise re-ask on
// every scroll. null means "not a DMCN identity" (unresolvable), which is exactly
// the legacy case. The promise itself is cached so N rows from one sender make ONE
// request.
const dirKeyCache = new Map<string, Promise<string | null>>();

export function directoryKey(
  address: string,
  lookup: (address: string) => Promise<IdentityLookupResponse>,
): Promise<string | null> {
  const key = address.trim().toLowerCase();
  let p = dirKeyCache.get(key);
  if (!p) {
    p = lookup(address)
      .then(r => (r.identity_unverifiable ? null : hexOfB64(r.ed25519_pub)))
      .catch(() => null);
    dirKeyCache.set(key, p);
  }
  return p;
}

// kindFromDirectory turns a cached directory answer into a row kind. When the
// message's own signing key is known (received mail) it must match what the
// directory publishes — a bridged message CLAIMING a DMCN address is signed by the
// bridge, not by that identity, so it must not earn the DMCN shield. That case
// returns 'unknown' rather than 'legacy': the reader raises it as a real warning,
// and the row makes no claim either way.
export function kindFromDirectory(dirKeyHex: string | null, messageKeyHex: string): SenderKind {
  if (!dirKeyHex) return 'legacy';
  if (messageKeyHex && dirKeyHex !== messageKeyHex.toLowerCase()) return 'unknown';
  return 'dmcn';
}
