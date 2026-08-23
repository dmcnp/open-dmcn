// Native-sender trust evaluation (whitepaper §14). Every inbox preview reaching
// the UI has already had its header signature verified in split.ts decryptHeader,
// so we KNOW the sender controls the key in the header. This module answers the
// second question — should the recipient trust that sender? — by anchoring the
// signature-verified header key to the public-key directory and to the owner's
// allowlist (contacts with a trust provenance).
//
// Modeled on crypto/bridgeAttest.ts: pure, never throws, resolves the directory
// via an injected lookup, and byte-compares keys. It computes only the
// directory/allowlist verdict; blocklist membership is layered on separately (it
// needs the mail-filter list), keeping this module directory-focused.

import { fromBase64 } from './keys';
import type { IdentityLookupResponse } from '../api/client';
import type { ContactRecord, TrustProvenance } from '../api/contactStore';

// TIER_DOMAIN_DNS mirrors identity.TierDomainDNS (Go) — a domain-anchored,
// countersigned identity. Kept in step with crypto/bridgeAttest.ts.
export const TIER_DOMAIN_DNS = 2;

// SenderTrustKind is the verdict, roughly in descending trust. The danger kinds
// (key_mismatch / key_changed / identity_unverifiable) are active warnings, not
// mere "unknown"; unknown_pending is the neutral default for a valid but
// unrecognised sender.
export type SenderTrustKind =
  | 'allowlisted'           // in the owner's allowlist (carries provenance)
  | 'domain_verified'       // not allowlisted, but domain-countersigned (tier ≥ DomainDNS)
  | 'unknown_pending'       // valid signature, registered, but no trust decision yet
  | 'key_mismatch'          // header key ≠ the directory's published key (danger)
  | 'key_changed'           // header key ≠ the key we pinned for this contact (danger)
  | 'identity_unverifiable' // directory says a claimed countersignature failed (danger)
  | 'directory_missing';    // sender not resolvable in the directory (warning)

export interface SenderTrust {
  kind: SenderTrustKind;
  provenance?: TrustProvenance; // set when kind === 'allowlisted'
  fingerprint?: string;         // directory fingerprint, for display
  reason?: string;              // human-readable detail for the danger/warning kinds
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// base64Eq compares a raw key against a base64-encoded one, never throwing on a
// malformed encoding (a bad base64 simply can't match).
function base64Eq(rawKey: Uint8Array, b64: string | undefined): boolean {
  if (!b64) return false;
  try {
    return bytesEqual(rawKey, fromBase64(b64));
  } catch {
    return false;
  }
}

export interface SenderTrustInput {
  senderAddress: string;
  senderPublicKey: Uint8Array; // ed25519 public from the (verified) signed header
  contact?: ContactRecord;     // the owner's allowlist entry for this sender, if any
}

// evaluateSenderTrust resolves the sender against the directory + allowlist and
// returns a trust verdict. lookup is the public-key directory (e.g. lookupIdentity).
// It never throws; a directory failure yields 'directory_missing'.
export async function evaluateSenderTrust(
  input: SenderTrustInput,
  lookup: (address: string) => Promise<IdentityLookupResponse>
): Promise<SenderTrust> {
  const { senderAddress, senderPublicKey, contact } = input;

  let dir: IdentityLookupResponse;
  try {
    dir = await lookup(senderAddress);
  } catch {
    // Not resolvable — still a validly-signed message, but we can't anchor it.
    return { kind: 'directory_missing', reason: 'sender not found in the directory' };
  }

  // A legacy (non-DMCN) sender: the lookup resolved this domain's BRIDGE, not a correspondent,
  // and there is no published identity key to compare against. Anchoring is impossible by
  // definition, so say that — the alternative is comparing the signing key against an absent one
  // and reporting a key MISMATCH, which reads as an impersonation attempt on perfectly ordinary
  // bridged mail. What vouches for a legacy sender is the bridge's signed SPF/DKIM/DMARC
  // attestation (crypto/bridgeAttest.ts), not the directory.
  if (dir.legacy) {
    return { kind: 'directory_missing', reason: 'sent from outside DMCN, via a bridge' };
  }

  // A claimed countersignature that failed to verify (revoked/unauthorized) — the
  // directory actively distrusts this identity. Mirrors bridgeAttest gap #9.
  if (dir.identity_unverifiable) {
    return { kind: 'identity_unverifiable', fingerprint: dir.fingerprint, reason: 'identity revoked or unverifiable' };
  }

  // The header sig is already verified, so a header-key ≠ directory-key means the
  // directory disowns the signing key (impersonation or a stale/forged message).
  if (!base64Eq(senderPublicKey, dir.ed25519_pub)) {
    return { kind: 'key_mismatch', fingerprint: dir.fingerprint, reason: 'signing key does not match the directory' };
  }

  // Pinned-key rotation: the directory agrees with the header, but it differs from
  // the key we pinned when this contact was allowlisted → treat as an unsigned
  // rotation (§14.1.2). Safe default: surface as danger and keep the sender pending
  // until re-verified. (Distinguishing a *signed* rotation needs directory rotation
  // lineage — see plan A4.)
  if (contact?.ed25519Pub && !base64Eq(senderPublicKey, contact.ed25519Pub)) {
    return { kind: 'key_changed', fingerprint: dir.fingerprint, reason: 'this contact’s key has changed — re-verify before trusting' };
  }

  // Allowlisted: any contact (contacts ARE the allowlist). Provenance labels the
  // strength; a contact added before this feature defaults to user_approved.
  if (contact) {
    return { kind: 'allowlisted', provenance: contact.provenance ?? 'user_approved', fingerprint: dir.fingerprint };
  }

  // Not allowlisted: domain-verified is a positive signal short of a trust decision.
  if ((dir.verified_tier ?? 0) >= TIER_DOMAIN_DNS) {
    return { kind: 'domain_verified', fingerprint: dir.fingerprint };
  }

  return { kind: 'unknown_pending', fingerprint: dir.fingerprint };
}
