import type { ContactRecord } from '../api/contactStore';
import type { KeyChange } from './lineage';

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
  adminKeyCustody: boolean;
  // noIdentity records the CONFIRMED ABSENCE of a DMCN identity: the owner was shown that a
  // counterparty they had verified now resolves to no record at all, and said that was
  // expected. It is a pinned state in its own right, not the lack of one.
  //
  // It has to be recorded rather than clearing the pin, or the absence becomes a laundering
  // step: withhold a record until the owner confirms "they left DMCN" and the pin is erased,
  // then serve an attacker's key, which a device with no pin takes as an ordinary first
  // sighting. Two moves, no warning at either. Keeping the absence pinned means the key that
  // appears afterwards is a CHANGE against something, and says so.
  noIdentity?: boolean;
}

// DirectoryFacts is the subset of IdentityLookupResponse a pin is taken from. Declared
// structurally rather than importing the response type so this module stays a leaf.
export interface DirectoryFacts {
  ed25519_pub: string;
  x25519_pub: string;
  admin_key_custody?: boolean;
  // Set by a directory that answers a lookup for a non-DMCN address by pointing at its
  // outbound bridge. A successful response carrying no identity is still an ANSWER about
  // this address, and a held pin has to be compared against it.
  legacy?: boolean;
}

export type PinVerdict =
  | 'unpinned'        // nothing recorded for this counterparty — nothing to compare
  | 'match'           // everything we pinned still holds
  | 'changed'         // the identity itself differs — danger; warned about, never refused
  | 'record_changed'; // keys hold, but a pinned property changed — warn, don't block

// absentIdentityFacts is what the directory offering NO identity for an address looks like as
// a fact set — the shape a legacy (bridge-only) address resolves to. Used both to compare
// against a held pin and, once the owner confirms it, to pin.
export function absentIdentityFacts(): PinnedFacts {
  return { ed25519Pub: '', x25519Pub: '', adminKeyCustody: false, noIdentity: true };
}

// directoryFacts projects a directory response onto the pinned fact set.
export function directoryFacts(dir: DirectoryFacts): PinnedFacts {
  // A legacy answer resolves to no identity at all; anything it does carry describes the
  // bridge, not the correspondent, and must not be pinned as if it were them.
  if (dir.legacy || !dir.ed25519_pub) return absentIdentityFacts();
  return {
    ed25519Pub: dir.ed25519_pub ?? '',
    x25519Pub: dir.x25519_pub ?? '',
    adminKeyCustody: dir.admin_key_custody === true,
  };
}

// contactFacts reads the facts pinned on a contact record, or undefined when the contact
// carries no pin (legacy v1/v2 rows, and keyless legacy-bridge entries that were never
// confirmed — which is different from one confirmed to have no identity, see noIdentity).
export function contactFacts(contact: ContactRecord | undefined): PinnedFacts | undefined {
  if (contact?.noIdentity) return absentIdentityFacts();
  if (!contact?.ed25519Pub) return undefined;
  return {
    ed25519Pub: contact.ed25519Pub,
    x25519Pub: contact.x25519Pub ?? '',
    adminKeyCustody: contact.adminKeyCustody === true,
  };
}

// changedFacts lists the pinned fields that differ, most severe first. Empty ⇒ match.
// A field absent from the PIN is never reported: a contact pinned before that field was
// covered has no recorded value for it, and treating "we didn't look" as "it changed"
// would fire on every pre-existing pin the first time this code runs.
export function changedFacts(pinned: PinnedFacts, observed: PinnedFacts): string[] {
  const out: string[] = [];
  // Gaining or losing a DMCN identity outranks everything else: it changes who can read mail
  // to this address, not merely which key seals it. Reported ALONE, because every key
  // difference that comes with it is a consequence of the identity going away, not a separate
  // finding — listing three changes for one event reads as three times the evidence.
  if (!!pinned.noIdentity !== !!observed.noIdentity) return ['DMCN identity'];
  if (pinned.ed25519Pub && pinned.ed25519Pub !== observed.ed25519Pub) out.push('signing key');
  if (pinned.x25519Pub && pinned.x25519Pub !== observed.x25519Pub) out.push('encryption key');
  // Named the way it reads in a sentence ("their key custody by their provider changed"), because
  // that is the only place it is ever shown. "admin key custody" is what the DAR bit is called;
  // it is not what to tell somebody deciding whether to reply.
  if (pinned.adminKeyCustody !== observed.adminKeyCustody) out.push('key custody by their provider');
  return out;
}

// checkPin compares a freshly resolved directory record against what we pinned.
// `observed` is undefined while the recipient is still being resolved.
// checkPin compares a freshly resolved directory record against what we pinned. `observed` is
// undefined while the recipient is still being RESOLVING — distinct from resolving to nothing,
// which is absentIdentityFacts() and is a comparable state.
export function checkPin(contact: ContactRecord | undefined, observed: PinnedFacts | undefined): PinVerdict {
  const pinned = contactFacts(contact);
  if (!pinned || !observed) return 'unpinned';
  // Nothing usable came back and it is not a confirmed absence either — treat it as unresolved
  // rather than inventing a verdict from a malformed record.
  if (!observed.ed25519Pub && !observed.noIdentity) return 'unpinned';
  const changed = changedFacts(pinned, observed);
  if (changed.length === 0) return 'match';
  // Appearing or disappearing from the directory is the same class of danger as a key swap:
  // mail that was sealed to this person would now be sealed to a bridge, or to a key nobody
  // has vouched for. Both are unrecoverable once sent.
  if (!!pinned.noIdentity !== !!observed.noIdentity) return 'changed';
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
 *
 * WRITTEN FOR THE PERSON READING IT, which took two passes to get right. The first version
 * explained the protocol — which key signed what, which enrolled device attested it — and that is
 * the wrong subject. The second still reached for it, offering what an ordinary re-key "looks
 * like" versus a takeover, which is speculation about a question the sentence cannot answer and
 * the reader cannot act on.
 *
 * What is left is what they need: the key changed, on this date, and here is what to do before
 * sending anything sensitive. A detail earns its place only by changing that answer — which is why
 * a key reported STOLEN says more (mail already received is suspect too, which is a second thing
 * to do) and an ordinary change says less. The mechanism belongs in trust/lineage.ts, where it
 * decides which of these sentences to show, not in the sentence.
 *
 * "Some other way" is spelled out as a phone call, a text, or a shared secret, because "confirm
 * out of band" is a phrase for people who already know what it means — and the ones who do not are
 * exactly the ones being asked to act on it.
 *
 * `change` is what the directory can prove (trust/lineage.ts), and it moves the sentence rather
 * than the outcome: a stolen key produces a perfectly signed rotation, so no amount of evidence
 * decides this for somebody. What it does decide is how alarmed to be, and "they say that key was
 * stolen" is not the same news as "their key changed".
 */
export function pinnedKeyWarning(address: string, change?: KeyChange): string {
  switch (change?.kind) {
    case 'reported-stolen':
      return `${address} reported the key you had verified as stolen, on ${onDate(change.at)}. Mail you already `
        + `received from them may have come from whoever took it, so treat that as suspect too. ${CHECK_FIRST}`;
    case 'replaced':
      return `The key for ${address} changed on ${onDate(change.at)}. ${CHECK_FIRST}`;
    case 'recovered':
      // One clause more than 'replaced', and only because it is the one difference that is about
      // THEM rather than about the protocol: the change was not approved by the key this person
      // checked. How the recovery arm works, and what it would look like in an impostor's hands,
      // are facts about the system — true, and not what somebody deciding whether to reply needs.
      return `The key for ${address} changed on ${onDate(change.at)}, and the change was not approved by the key `
        + `you verified. ${CHECK_FIRST}`;
    default:
      return `The key for ${address} has changed since you verified them, and there is no record of why. ${CHECK_FIRST}`;
  }
}

/**
 * What to do about any of it, in the same words every time.
 *
 * One sentence, and it is the only part that asks anything of the reader. The routes are named
 * because a person told to "verify out of band" has been given a task without a method — and the
 * method is the whole point: it has to be a channel an attacker holding this address does not
 * control.
 */
const CHECK_FIRST = 'Avoid sending anything sensitive until you have checked with them another way: a phone call, '
  + 'a text message, or something only the two of you would know.';

/** A date a person can repeat back over the phone, in their own locale. */
function onDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/**
 * pinnedIdentityGoneWarning covers the other direction: an address you verified as a DMCN
 * correspondent now resolves to no identity at all, so mail to it would leave over a bridge as
 * ordinary email — readable by that bridge and every hop after it.
 *
 * Worded as a downgrade rather than an error because it can legitimately be one (they closed
 * the account), and because the thing the reader needs to weigh is what sending now would
 * actually do, not whose fault it is. A fleet that simply withholds one record produces this
 * exact signal, which is why it is shown this prominently — and why it is still shown rather than
 * acted on: whether to send anyway is the sender's call, not the client's.
 */
export function pinnedIdentityGoneWarning(address: string): string {
  return `${address} no longer has a DMCN account, though you verified one before. Mail you send now would go out as `
    + `ordinary email, which every service that handles it on the way can read. ${CHECK_FIRST}`;
}

/**
 * pinnedRecordWarning is the softer counterpart: the keys still match, but something else
 * we pinned about this identity moved. Worth showing — a domain turning on admin key
 * custody means someone other than the account holder may now hold their keys — but not
 * worth blocking a send over, since no message is mis-sealed by it.
 */
export function pinnedRecordWarning(address: string, changed: string[]): string {
  const what = changed.length ? changed.join(' and ') : 'identity record';
  return `${address}'s ${what} changed since you verified them. Their keys are the same, so mail to them can still `
    + `only be read by them. This was not a change they made, so check that it is expected.`;
}
