import type { ContactRecord } from '../api/contactStore';

// Pinned-identity checking: comparing what the directory hands us NOW against what we
// recorded when we first confirmed this counterparty.
//
// This is the only protection that survives a hostile or compromised fleet. Everything
// else in the trust chain is verified against the domain's authority record, which the
// fleet serves — so a fleet that controls both what it serves and what it withholds can
// present a re-bound identity and simply never hand out the tombstone that would reveal
// it. Nor does anything force a fleet to serve the SAME record to two observers: every
// admission check (relay/acceptrecord.go) is local to one node's store, and a resolve
// stops at the first seed that verifies, so two valid revisions of one address can be
// served to two peers with nothing to reconcile them.
//
// A pin is the local counterweight to that, which is why the copy that decides lives in
// this device's IndexedDB (trust/pinStore.ts) rather than in the personal KV. The KV
// copy still exists and still syncs the pin between the owner's devices, but it is
// hosted by the same relay a pin exists to catch: it can be withheld or rolled back to a
// state before the pin was taken. Source of truth local, sync via the KV — see
// reconcilePin.
//
// It is deliberately not a claim that a change is malicious. A legitimate rotation (a
// lost device, an offboarded employee re-provisioned by an admin) produces exactly the
// same signal. The point is that the change becomes VISIBLE and the user gets to decide,
// rather than the swap being silent.

// PinnedFacts is what a pin actually covers. Each field is here because a silent change
// to it is a security event that the others would not catch:
//
//   ed25519Pub  — the signing key. A change is a re-binding of the address.
//   x25519Pub   — the ENCRYPTION key. Covered by the owner self-signature like the
//                 signing key, but a separate field: mail is sealed to this one, so a
//                 swap here is what actually makes a message readable by someone else.
//                 It was stored but never compared until now.
//   adminKeyCustody — the domain's DAR custody policy. Operator-controlled and NOT
//                 covered by any owner signature, so this is the field a compelled
//                 operator can flip without touching a user key. false → true means the
//                 domain now asserts that an admin holds this account's keys.
//   bridgeCapability — owner-signed; a contact silently becoming a bridge changes what
//                 their mail means (bridged mail carries a classification, not authorship).
//
// Deliberately NOT pinned: `fingerprint` is derived from the two keys (identity.go
// fingerprintOf), so comparing it is redundant with comparing them. `verified_tier`
// legitimately increases when a domain countersigns. `require_onion` and RelayHints
// legitimately change on any operator rebalance/drain, so pinning them would produce
// constant false alarms — routing equivocation needs cross-seed comparison at resolve
// time, not a pin.
export interface PinnedFacts {
  ed25519Pub: string; // base64 std, as served by the directory
  x25519Pub: string;  // base64 std
  bridgeCapability: boolean;
  adminKeyCustody: boolean;
}

// DirectoryFacts is the subset of IdentityLookupResponse a pin is taken from. Declared
// structurally rather than importing the response type so this module stays a leaf.
export interface DirectoryFacts {
  ed25519_pub: string;
  x25519_pub: string;
  bridge_capability?: boolean;
  admin_key_custody?: boolean;
}

export type PinVerdict =
  | 'unpinned'        // nothing recorded for this counterparty — nothing to compare
  | 'match'           // everything we pinned still holds
  | 'changed'         // an identity KEY differs — danger; blocks a send
  | 'record_changed'; // keys hold, but a pinned property changed — warn, don't block

// directoryFacts projects a directory response onto the pinned fact set.
export function directoryFacts(dir: DirectoryFacts): PinnedFacts {
  return {
    ed25519Pub: dir.ed25519_pub ?? '',
    x25519Pub: dir.x25519_pub ?? '',
    bridgeCapability: dir.bridge_capability === true,
    adminKeyCustody: dir.admin_key_custody === true,
  };
}

// contactFacts reads the facts pinned on a contact record, or undefined when the contact
// carries no pin (legacy v1/v2 rows, keyless legacy-bridge allowlist entries).
export function contactFacts(contact: ContactRecord | undefined): PinnedFacts | undefined {
  if (!contact?.ed25519Pub) return undefined;
  return {
    ed25519Pub: contact.ed25519Pub,
    x25519Pub: contact.x25519Pub ?? '',
    bridgeCapability: contact.bridgeCapability === true,
    adminKeyCustody: contact.adminKeyCustody === true,
  };
}

// changedFacts lists the pinned fields that differ, most severe first. Empty ⇒ match.
// A field absent from the PIN is never reported: a contact pinned before that field was
// covered has no recorded value for it, and treating "we didn't look" as "it changed"
// would fire on every pre-existing pin the first time this code runs.
export function changedFacts(pinned: PinnedFacts, observed: PinnedFacts): string[] {
  const out: string[] = [];
  if (pinned.ed25519Pub && pinned.ed25519Pub !== observed.ed25519Pub) out.push('signing key');
  if (pinned.x25519Pub && pinned.x25519Pub !== observed.x25519Pub) out.push('encryption key');
  if (pinned.adminKeyCustody !== observed.adminKeyCustody) out.push('admin key custody');
  if (pinned.bridgeCapability !== observed.bridgeCapability) out.push('bridge capability');
  return out;
}

// checkPin compares a freshly resolved directory record against what we pinned.
// `observed` is undefined while the recipient is still being resolved.
export function checkPin(contact: ContactRecord | undefined, observed: PinnedFacts | undefined): PinVerdict {
  const pinned = contactFacts(contact);
  if (!pinned || !observed?.ed25519Pub) return 'unpinned';
  const changed = changedFacts(pinned, observed);
  if (changed.length === 0) return 'match';
  // A key change outranks a property change: it is the unrecoverable one.
  if (pinned.ed25519Pub !== observed.ed25519Pub) return 'changed';
  if (pinned.x25519Pub && pinned.x25519Pub !== observed.x25519Pub) return 'changed';
  return 'record_changed';
}

/** hasPinnedKey reports whether a contact carries key-change protection at all. */
export function hasPinnedKey(contact: ContactRecord | undefined): boolean {
  return Boolean(contact?.ed25519Pub);
}

/**
 * pinnedKeyWarning is the user-facing text for a changed key. Kept here so the reader, the
 * composer and the contact list say the same thing about the same event — a key change means the
 * same thing wherever it surfaces, and three near-miss wordings would read as three different
 * severities.
 */
export function pinnedKeyWarning(address: string): string {
  return `${address}'s key has changed since you verified them. That can be a normal rotation — a lost device, or an admin re-provisioning the account — or someone else now holding the address. Confirm with them out of band before sending anything sensitive.`;
}

/**
 * pinnedRecordWarning is the softer counterpart: the keys still match, but something else
 * we pinned about this identity moved. Worth showing — a domain turning on admin key
 * custody means someone other than the account holder may now hold their keys — but not
 * worth blocking a send over, since no message is mis-sealed by it.
 */
export function pinnedRecordWarning(address: string, changed: string[]): string {
  const what = changed.length ? changed.join(' and ') : 'identity record';
  return `${address}'s ${what} changed since you verified them. Their keys are unchanged, so mail to them is still sealed to the same person — but the change was not something they signed, so confirm it is expected.`;
}
