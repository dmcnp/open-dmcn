// What happened to the key you pinned.
//
// A pin tells you a counterparty's key is no longer the one you verified. That is where the
// protection ends and this begins: the directory may be able to say WHY, and the three answers
// call for different things from the person reading them.
//
//   replaced       — the key you pinned signed the handover to the one in use now. Ordinary
//                    re-keying looks like this. So does a takeover by someone who had both the
//                    key and an enrolled device, which is why it is evidence rather than a verdict.
//   recovered      — the handover was signed by some OTHER key, which the entry says was the
//                    address's recovery key. That is a real and legitimate arm — it is how
//                    someone who lost every device gets back in — but it is NOT the key you
//                    verified, and this client cannot check that the key which signed was ever
//                    theirs. A forged chain looks exactly like this, so it is reported as its own
//                    thing rather than folded into "replaced".
//   reported-stolen— the owner published a tombstone against the key you pinned, signed by the key
//                    that replaced it. That is a warning about the past as well as the present:
//                    mail already signed by the old key is suspect too.
//   unexplained    — nothing signed accounts for the change. An unsigned substitution looks like
//                    this, and so does a fleet withholding the evidence.
//
// None of them unblocks anything. A key change is always put to the person who pinned it (see
// whitepaper §14.1.2, amended): a stolen key produces a perfectly signed rotation, so the moment
// their binding changes is the one moment a takeover becomes visible to them, and spending it on
// a notification nobody has to read gives it away. What this module changes is what they are
// shown while they decide.
//
// EVERYTHING here is verified in the browser. The fleet is the party a pin exists to catch, so a
// lineage it merely asserted would be no counterweight at all — a chain that does not hold up is
// treated as no explanation rather than as a bad one.
import { fetchIdentityRecord, type IdentityRecordResponse } from '../api/client';
import { decodeAddressHistory, decodeAddressRemoval, decodeIdentityRecord, encodeIdentitySignableBytes, encodeRemovalSignableBytes } from '../crypto/protobuf';
import { removalSigningBytes, verifySelfSignature } from '../crypto/identity';
import { verifyChainLinks, verifyHistory, verifyRecordChain } from '../crypto/verifyRotation';
import { fromBase64, toBase64 } from '../crypto/keys';
import { verify } from '../crypto/sign';

export type KeyChange =
  | { kind: 'replaced'; at: number }
  | { kind: 'recovered'; at: number }
  | { kind: 'reported-stolen'; at: number }
  | { kind: 'unexplained' };

/**
 * Explain a pinned key's disappearance from the given directory answer.
 *
 * Pure apart from the crypto: the caller supplies what the directory served, so this is testable
 * without a fleet — which matters, because the interesting cases are the ones where the answer is
 * forged or incomplete.
 */
export async function explainKeyChange(
  address: string,
  pinnedEd25519Pub: string,
  served: IdentityRecordResponse,
): Promise<KeyChange> {
  const rec = await decodeIdentityRecord(fromBase64(served.record));
  // A record that does not verify explains nothing, and neither does one for another address.
  if (String(rec.address ?? '').toLowerCase() !== address.toLowerCase()) return { kind: 'unexplained' };
  // The owner's own signature over the record, checked before anything is read out of it. The
  // chain walk below only proves the entries agree with EACH OTHER and with the keys this record
  // publishes; it says nothing about whether the owner published them.
  if (!await verifySelfSignature(rec.ed25519PublicKey, await encodeIdentitySignableBytes(rec), rec.selfSignature)) {
    return { kind: 'unexplained' };
  }
  if (await verifyRecordChain(rec)) return { kind: 'unexplained' };

  // A tombstone outranks a rotation: "this key was stolen" is the heavier statement, and it is
  // the one the reader needs first.
  const stolenAt = await declaredStolen(address, pinnedEd25519Pub, rec, served.removal);
  if (stolenAt !== null) return { kind: 'reported-stolen', at: stolenAt };

  const handover = await retiredInLineage(address, pinnedEd25519Pub, rec, served.history);
  if (handover) return { kind: handover.byRecoveryKey ? 'recovered' : 'replaced', at: handover.at };
  return { kind: 'unexplained' };
}

/** Fetch the directory's answer for an address and explain a pinned key against it. */
export async function loadKeyChange(address: string, pinnedEd25519Pub: string): Promise<KeyChange> {
  try {
    return await explainKeyChange(address, pinnedEd25519Pub, await fetchIdentityRecord(address));
  } catch {
    // Unreachable, or a deployment whose backend does not serve records. Neither is evidence of
    // anything, and the block stands either way — so the reader is told less, never more.
    return { kind: 'unexplained' };
  }
}

/** A transition that retired the pinned key: when, and whether the pinned key itself signed it. */
interface Handover {
  at: number;
  /** The consent came from a key other than the one retired — the recovery arm, or a forgery. */
  byRecoveryKey: boolean;
}

/**
 * When the pinned key handed the address over, or null if nothing signed says it did.
 *
 * The record's own chain is capped, so an older key may have fallen out of it — that is what the
 * history record is for, and it is only consulted when the capped chain comes up short.
 */
async function retiredInLineage(
  address: string,
  pinned: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rec: any,
  history?: string,
): Promise<Handover | null> {
  const onRecord = retiredAt(rec.rotationChain ?? [], pinned);
  if (onRecord) return onRecord;
  if (!history) return null;
  const h = await decodeAddressHistory(fromBase64(history));
  if (await verifyHistory(h, address)) return null;
  // The history has to agree with the record it explains, or it describes some other lineage.
  const chain = h.chain ?? [];
  const last = chain[chain.length - 1];
  if (!last || toBase64(last.nextEd25519PublicKey) !== toBase64(rec.ed25519PublicKey)) return null;
  if (await verifyChainLinks(chain, address)) return null;
  return retiredAt(chain, pinned);
}

/**
 * The transition that retired `pinned`, or null — and crucially, WHO authorized it.
 *
 * Matching on the retired key alone is not enough, and the gap is the whole reason this returns a
 * shape rather than a time. An entry's consent signature is checked against the key the entry
 * ITSELF names in `authorizingEd25519PublicKey`, which is legitimately allowed to differ from the
 * retired one — that is the recovery arm. Go closes the gap for the terminal entry at admission,
 * against a record the node already holds; this client has no such anchor. So an attacker
 * publishing a substituted record with a one-entry chain claiming `retired = <the key you
 * verified>` and `authorizing = <their own key>` produces a chain that verifies end to end.
 *
 * What is actually checkable here is narrower and is what gets the reassuring wording: the pinned
 * key signed its OWN retirement. Anything else is reported as the weaker thing it is.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function retiredAt(chain: any[], pinned: string): Handover | null {
  for (const e of chain) {
    if (toBase64(e.retiredEd25519PublicKey) !== pinned) continue;
    return {
      at: Number(e.rotatedAt),
      byRecoveryKey: toBase64(e.authorizingEd25519PublicKey ?? new Uint8Array()) !== pinned,
    };
  }
  return null;
}

/**
 * When the owner declared the pinned key stolen, or null.
 *
 * The declaration is signed by the key that TOOK the address over, which is what makes it worth
 * anything: a stolen key is held by both parties and identifies neither. So the signature is
 * checked against the key the address is bound to NOW, and a tombstone signed by anyone else —
 * including a domain root, which this client cannot verify without the domain's authority record
 * — is left out of the account rather than guessed at.
 */
async function declaredStolen(
  address: string,
  pinned: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  rec: any,
  removal?: string,
): Promise<number | null> {
  if (!removal) return null;
  const rm = await decodeAddressRemoval(fromBase64(removal));
  if (String(rm.address ?? '').toLowerCase() !== address.toLowerCase()) return null;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const hit = (rm.removedBindings ?? []).find((b: any) => toBase64(b.ed25519PublicKey) === pinned);
  if (!hit) return null;

  const signable = await encodeRemovalSignableBytes({
    version: Number(rm.version ?? 0),
    domain: String(rm.domain ?? ''),
    address: String(rm.address ?? ''),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    removedBindings: (rm.removedBindings ?? []).map((b: any) => ({
      ed25519PublicKey: b.ed25519PublicKey,
      removedAt: Number(b.removedAt ?? 0),
    })),
    revision: Number(rm.revision ?? 0),
    createdAt: Number(rm.createdAt ?? 0),
  });
  try {
    const ok = await verify(rec.ed25519PublicKey, removalSigningBytes(signable), rm.selfSignature);
    return ok ? Number(hit.removedAt) : null;
  } catch {
    return null;
  }
}
