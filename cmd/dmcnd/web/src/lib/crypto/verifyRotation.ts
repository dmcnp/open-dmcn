// Verifying an address's rotation chain, in the browser.
//
// This has to happen here rather than on a server, and that is the whole point of the module.
// A pin exists to catch a fleet that serves one thing to one observer and another to another; a
// lineage that same fleet vouched for would be no counterweight at all. So the client checks the
// signatures itself, against bytes it re-encodes itself, and a chain that does not hold up is
// treated as no explanation rather than as a bad one.
//
// Mirrors Go's identity.VerifyRotationChain / verifyChainLinks / RotationEntry.Verify — the two
// have to agree, because a chain this refuses is one the user is told nothing about, and a chain
// this accepts that Go would refuse is worse.
//
// Deliberately NOT checked here: whether the device credential chains to the domain authority and
// clears its tenure minimum. That is an admission-time question about the TERMINAL entry, asked
// by every node against the rotation's own time (identity.AuthorizeRebind); re-asking it during a
// history walk would fail every past entry the moment its credential expired.
import {
  encodeRotationAcceptBytes, encodeRotationConsentBytes, encodeRotationDeviceBytes,
} from './protobuf';
import { ROTATION_ACCEPT_CTX, ROTATION_CTX, ROTATION_DEVICE_CTX } from './identity';
import { bufferSource } from './bytes';
import { verify } from './sign';

/**
 * A decoded rotation entry.
 *
 * Typed loosely on purpose: what arrives is a protobufjs message whose 64-bit fields are Longs,
 * and it is handed straight back to the encoders so the bytes it was signed over are reproduced
 * exactly. Reading it field by field into a tidy shape is what would break that.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type DecodedEntry = any;

/**
 * MAX_ROTATION_CHAIN must match Go's identity.MaxRotationChain.
 *
 * A record carrying more is refused outright, so a client that drifted above it would publish
 * records nothing on the network would accept.
 *
 * It lives with the VERIFIER rather than with the ceremony because this module is a leaf: the
 * trust path reads it on every changed key, and the ceremony imports the deployment seam. An
 * edge from here to there would pull the whole product graph into a read.
 */
export const MAX_ROTATION_CHAIN = 8;

const ED25519_SIZE = 32;

/** Whether the chain's oldest entry names a predecessor that is absent — i.e. it was truncated. */
export function chainTruncated(chain: DecodedEntry[]): boolean {
  return chain.length > 0 && (chain[0].prevSignatureHash?.length ?? 0) > 0;
}

/**
 * Check one entry's own signatures and shape. Returns '' when it holds up.
 *
 * Three signatures nest, each covering the ones before it: the device attests, the outgoing key
 * consents to a transition already naming that device, and the incoming key accepts the whole
 * thing. That nesting is what stops a signature being lifted from one handover onto another, so
 * all three are re-derived here rather than trusted as a set.
 */
export async function verifyRotationEntry(e: DecodedEntry): Promise<string> {
  if (!Number(e.version)) return 'version is unset';
  if (!e.address) return 'the entry names no address';
  for (const [name, key] of [
    ['retired', e.retiredEd25519PublicKey],
    ['next', e.nextEd25519PublicKey],
    ['authorizing', e.authorizingEd25519PublicKey],
  ] as const) {
    if ((key?.length ?? 0) !== ED25519_SIZE) return `the ${name} key is the wrong size`;
  }
  // A transition to the key already held is not a transition, and admitting one would let an
  // entry be replayed as a no-op that still advances the chain.
  if (sameBytes(e.retiredEd25519PublicKey, e.nextEd25519PublicKey)) return 'the retired and next keys are the same';
  if (sameBytes(e.retiredX25519PublicKey, e.nextX25519PublicKey)) return 'the retired and next mailbox keys are the same';
  if (!Number(e.rotatedAt)) return 'rotated_at is unset';
  if (!Number(e.nextRevision)) return 'next_revision is unset';
  const hashLen = e.prevSignatureHash?.length ?? 0;
  if (hashLen !== 0 && hashLen !== 32) return 'prev_signature_hash is the wrong size';

  if (!await verifyCtx(e.authorizingEd25519PublicKey, ROTATION_CTX, await encodeRotationConsentBytes(e), e.signature)) {
    return 'the outgoing key did not consent to this transition';
  }
  if (e.deviceCredential) {
    const subject = e.deviceCredential.subject;
    if (!await verifyCtx(subject, ROTATION_DEVICE_CTX, await encodeRotationDeviceBytes(e), e.deviceSignature)) {
      return 'the named device did not attest this transition';
    }
  } else if ((e.deviceSignature?.length ?? 0) > 0) {
    return 'a device signature with no credential names no device';
  }
  if (!await verifyCtx(e.nextEd25519PublicKey, ROTATION_ACCEPT_CTX, await encodeRotationAcceptBytes(e), e.nextSignature)) {
    return 'the incoming key did not accept this transition';
  }
  return '';
}

/**
 * Check that the entries form one unbroken line for one address. Returns '' when they do.
 *
 * Each entry has to retire the key its predecessor handed over, name that predecessor by the hash
 * of its signature, and advance in both time and revision — so entries cannot be reordered,
 * dropped from the middle, or borrowed from another address's history.
 */
export async function verifyChainLinks(chain: DecodedEntry[], address: string): Promise<string> {
  for (let i = 0; i < chain.length; i++) {
    const e = chain[i];
    const bad = await verifyRotationEntry(e);
    if (bad) return `entry ${i}: ${bad}`;
    // Every entry names the address it belongs to, so a transition genuinely signed for one
    // address cannot be replayed into another address's history.
    if (String(e.address).toLowerCase() !== address.toLowerCase()) {
      return `entry ${i} is for ${e.address}, not ${address}`;
    }
    if (i === 0) continue;
    const prev = chain[i - 1];
    if (!sameBytes(e.retiredEd25519PublicKey, prev.nextEd25519PublicKey)
      || !sameBytes(e.retiredX25519PublicKey, prev.nextX25519PublicKey)) {
      return `entry ${i} retires a key entry ${i - 1} did not hand over`;
    }
    if (!sameBytes(e.prevSignatureHash, await sha256(prev.signature))) {
      return `entry ${i} does not chain to entry ${i - 1}`;
    }
    if (Number(e.rotatedAt) <= Number(prev.rotatedAt)) return `entry ${i} is not after entry ${i - 1} in time`;
    if (Number(e.nextRevision) <= Number(prev.nextRevision)) return `entry ${i} does not advance the revision`;
  }
  return '';
}

/**
 * Verify the chain a record carries, and that it lands on that record. Returns '' when it does.
 *
 * The terminal check is what stops a genuine chain ending in some key being carried by a record
 * that publishes a different one — a chain is evidence about ONE handover into ONE record, never
 * a transferable credential.
 */
export async function verifyRecordChain(rec: DecodedEntry): Promise<string> {
  const chain: DecodedEntry[] = rec.rotationChain ?? [];
  if (chain.length === 0) return '';
  if (chain.length > MAX_ROTATION_CHAIN) return 'the chain carries more entries than the network accepts';
  const bad = await verifyChainLinks(chain, String(rec.address));
  if (bad) return bad;

  const last = chain[chain.length - 1];
  if (!sameBytes(last.nextEd25519PublicKey, rec.ed25519PublicKey)
    || !sameBytes(last.nextX25519PublicKey, rec.x25519PublicKey)) {
    return 'the last transition hands over to a different key than this record publishes';
  }
  if (Number(last.nextRevision) !== Number(rec.revision)) {
    return 'the last transition mints a different revision than this record carries';
  }
  return '';
}

/**
 * Verify a complete address history. Returns '' when it holds up.
 *
 * A history that has been truncated at the front is refused outright: this record is exactly
 * where a reader goes when the capped on-record chain already fell short, so one that starts
 * part-way through defeats its own purpose.
 */
export async function verifyHistory(history: DecodedEntry, address: string): Promise<string> {
  if (String(history.address ?? '').toLowerCase() !== address.toLowerCase()) {
    return 'the history is for a different address';
  }
  const chain: DecodedEntry[] = history.chain ?? [];
  if (chainTruncated(chain)) return 'the history does not begin at the first rotation';
  return verifyChainLinks(chain, address);
}

async function verifyCtx(pub: Uint8Array, ctx: Uint8Array, body: Uint8Array, signature?: Uint8Array): Promise<boolean> {
  if (!pub?.length || !signature?.length) return false;
  const buf = new Uint8Array(ctx.length + body.length);
  buf.set(ctx, 0);
  buf.set(body, ctx.length);
  try {
    return await verify(pub, buf, signature);
  } catch {
    // A malformed key or signature is a failed verification, and reads as one.
    return false;
  }
}

async function sha256(data?: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data ?? new Uint8Array(0))));
}

function sameBytes(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
