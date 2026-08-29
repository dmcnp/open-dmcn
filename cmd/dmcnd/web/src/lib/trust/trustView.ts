// Shared display mapping for trust signals (§14). Keeps the badge vocabulary — the
// same variant/icon language crypto-badge already uses in MessageReader's
// attestationView — in one place, so contacts and the message reader stay in sync.

import type { TrustProvenance } from '../api/contactStore';
import type { SenderTrust } from '../crypto/senderTrust';

export type BadgeVariant = 'neutral' | 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'trust-contact' | 'trust-dmcn';
export type TrustIcon = 'shield-check' | 'alert-triangle';

export interface TrustView {
  variant: BadgeVariant;
  icon: TrustIcon;
  label: string;
  detail: string;
}

// provenanceView maps an allowlist trust provenance to its badge (§14.1.1),
// strongest → weakest. Every provenance is a TRUSTED CONTACT, so they all use the
// blue "trust-contact" colour (matching the compose recipient shields); the label
// conveys the verification strength. DMCN-but-not-a-contact senders are teal (see
// senderTrustView 'domain_verified').
export function provenanceView(p: TrustProvenance): { variant: BadgeVariant; label: string } {
  switch (p) {
    case 'in_person':       return { variant: 'trust-contact', label: 'Verified in person' };
    case 'fingerprint':     return { variant: 'trust-contact', label: 'Fingerprint verified' };
    case 'network_vouched': return { variant: 'trust-contact', label: 'Network vouched' };
    case 'org_verified':    return { variant: 'trust-contact', label: 'Organisationally verified' };
    case 'user_approved':   return { variant: 'trust-contact', label: 'Trusted sender' };
  }
}

// senderTrustView maps a received-message trust verdict to its reader badge +
// detail callout. Danger kinds are active warnings, not merely "unknown".
export function senderTrustView(t: SenderTrust): TrustView {
  switch (t.kind) {
    case 'allowlisted': {
      // Trusted contact → blue (matches the compose recipient shields).
      const pv = t.provenance ? provenanceView(t.provenance) : { variant: 'trust-contact' as BadgeVariant, label: 'Trusted sender' };
      return { variant: pv.variant, icon: 'shield-check', label: pv.label, detail: 'This is from a trusted sender in your contacts — their identity is confirmed.' };
    }
    case 'domain_verified':
      // DMCN identity, not (yet) a contact → brand teal (matches the compose recipient shields).
      return { variant: 'trust-dmcn', icon: 'shield-check', label: 'DMCN sender', detail: 'This sender is a verified DMCN identity (their domain has cryptographically countersigned their address), but you have not added them to your contacts yet.' };
    case 'unknown_pending':
      return { variant: 'warning', icon: 'alert-triangle', label: 'Unknown sender', detail: 'You have never confirmed this sender’s identity. Their message is genuine and untampered, but treat unexpected requests with caution.' };
    case 'key_mismatch':
      return { variant: 'danger', icon: 'alert-triangle', label: 'Key does not match directory', detail: 'The key that signed this message is not the one published for this address in the directory. This may be an impersonation attempt — do not trust it.' };
    case 'key_changed':
      return { variant: 'danger', icon: 'alert-triangle', label: 'Sender’s key changed', detail: 'This contact’s signing key has changed since you allowlisted them. Re-verify their identity out of band before trusting this message.' };
    case 'record_changed':
      // Deliberately WARNING, not danger: the keys still hold, so nothing is mis-sealed
      // and no impersonation is implied. What changed is a property nobody signed —
      // most importantly a domain asserting admin key custody over the account.
      return { variant: 'warning', icon: 'alert-triangle', label: 'Sender’s record changed', detail: t.reason ? `${t.reason[0].toUpperCase()}${t.reason.slice(1)}. Their keys are unchanged, so this message is genuinely from them — but the change was not something they signed, so confirm it is expected.` : 'Something this contact’s identity record declares has changed since you verified them, without any change to their keys.' };
    case 'identity_unverifiable':
      return { variant: 'danger', icon: 'alert-triangle', label: 'Unverifiable identity', detail: 'The directory reports this identity claimed a domain countersignature that failed to verify (revoked or unauthorized). Do not trust it.' };
    case 'directory_missing':
      return { variant: 'warning', icon: 'alert-triangle', label: 'Sender not in directory', detail: 'This sender could not be found in the public-key directory, so their identity cannot be independently confirmed right now.' };
  }
}
