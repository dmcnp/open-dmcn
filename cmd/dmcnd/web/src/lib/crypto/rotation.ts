// Re-keying an account, from the browser.
//
// A rotation replaces the keypair an address is bound to while keeping the address, the mailbox
// and everything in it. The owner proves continuity — the outgoing key consents, the incoming key
// accepts, an enrolled device attests — and no operator is involved in authorising it.
//
// ORDER IS THE SUBSTANCE OF THIS MODULE. Several steps are irreversible on their own, and doing
// them in the wrong sequence produces failures a user cannot recover from:
//
//   - the local checkpoint is written BEFORE any network call, so a ceremony interrupted after
//     publishing can be finished rather than leaving a user holding a key nobody accepts;
//   - the outgoing generation is retained BEFORE the keystore is re-wrapped, because that is the
//     only moment both generations exist on the device;
//   - the push scope is torn down BEFORE the swap, since its identifier derives from the old
//     mailbox key and becomes unreachable the instant that changes;
//   - the mailbox is re-keyed on the relay AFTER the record publishes, because the relay derives
//     the previous mailbox key from the record's own rotation chain.
//
// What it deliberately does NOT do is re-seal anything. Mail and personal storage stay sealed to
// the generation they were written under, and the retired-key ring is what keeps them readable.
// Re-sealing eagerly would mean downloading and rewriting an entire mailbox inside a ceremony
// that must be short enough to finish.
import { deployment } from '@deployment';
import {
  encodeIdentityRecord, encodeIdentitySignableBytes, encodeRemovalRecord,
  encodeRemovalSignableBytes, encodeRotationAcceptBytes, encodeRotationConsentBytes,
  encodeRotationDeviceBytes, type RotationEntryWire,
} from './protobuf';
import {
  ROTATION_ACCEPT_CTX, ROTATION_CTX, ROTATION_DEVICE_CTX, removalSigningBytes, signSelfSignature,
} from './identity';
import { generateIdentityKeyPair, type IdentityKeyPair } from './keys';
import { bufferSource } from './bytes';
import { sign } from './sign';
import { retainRetiredFromKeyPair } from './retiredKeys';
import { MAX_ROTATION_CHAIN } from './verifyRotation';
import type { FilterList } from '../api/filterList';

/** How far a ceremony has got, so an interrupted one resumes instead of starting over. */
export type RotationPhase =
  | 'signed'     // the new record exists locally; nothing has been published
  | 'published'  // the directory has it — the point of no return
  | 'rekeyed';   // the mailbox has moved to the new key

export interface RotationCheckpoint {
  address: string;
  phase: RotationPhase;
  startedAt: number;
  /** Public halves only — enough to recognise the state, never enough to act. */
  oldEd25519Public: Uint8Array;
  newEd25519Public: Uint8Array;
  /**
   * The mail filter, carried across the re-key.
   *
   * The relay holds it sealed to the OUTGOING key and cannot re-seal what it cannot read, so the
   * re-key drops it and the client puts it back. It rides on the checkpoint because a ceremony
   * that resumes after the swap can no longer read the original — the old key is retired and the
   * relay has already let the list go.
   */
  mailFilter?: FilterList;
  /**
   * The tombstones a compromised re-key publishes, kept so a resumed ceremony still publishes
   * them. Losing them would leave the account re-keyed and its contacts told only that the key
   * changed — the softer of the two statements, and the wrong one.
   */
  compromise?: CompromiseDeclaration[];
}

/** Everything the ceremony needs that this module will not fetch for itself. */
export interface RotationInputs {
  address: string;
  /**
   * This device's enrolled signing key, supplied by the caller.
   *
   * Taken as an input rather than loaded here so the ceremony has no hidden dependency on local
   * storage: what it needs is a signer, and where that comes from is the caller's business. It
   * also means the ordering can be exercised without a browser.
   */
  device: { publicKey: Uint8Array; sign(data: Uint8Array): Promise<Uint8Array> };
  /** The outgoing generation's HKDF alias root, retained so throwaway aliases stay readable. */
  outgoingAliasRoot?: CryptoKey;
  /** The outgoing keypair's raw bytes, from a fresh re-auth. */
  current: IdentityKeyPair;
  /** The record being displaced, as the directory currently holds it. */
  currentRecord: RecordState;
  /**
   * Whether the retiring key is being declared compromised. Defaults to `routine`.
   *
   * The owner's statement, and only they can make it: the tombstone is signed by the INCOMING
   * key, which is exactly the key a thief who rotated the address would hold instead. That is
   * also why it is a better shape than the whitepaper's original COMPROMISE declaration signed
   * by the compromised key itself — a key a thief holds too.
   */
  severity?: RotationSeverity;
  /** The address's existing tombstones, so a new one EXTENDS them rather than dropping any. */
  priorRemoval?: RemovalState;
  /** The device credential this device was enrolled with — its date is what tenure is judged on. */
  deviceCredential: Uint8Array;
  /**
   * The address's complete history so far, which this rotation extends.
   *
   * Distinct from `currentRecord.rotationChain`, which is the CAPPED window the record carries.
   * Publishing the capped one as the history would quietly discard an account's older
   * transitions the first time it exceeded the cap — exactly the reader this record exists for.
   */
  priorHistory: RotationEntryWire[];
  /**
   * The other addresses answering to this same keypair, re-keyed in the same ceremony.
   *
   * A shared alias is the account's own keypair under another name, so one left behind keeps the
   * retired key able to open this mailbox under that name — which is the one thing a rotation
   * exists to end. Every sibling moves to the SAME new keypair, so the mailbox stays one mailbox.
   *
   * The caller enumerates them, and is responsible for refusing to start when it cannot: a
   * ceremony that quietly skipped one would report success while leaving the old key live.
   */
  siblings?: SiblingInput[];
}

/**
 * How bad this re-key is, which is a different fact from the fact that it happened.
 *
 * `routine` is a scheduled or precautionary change of key. `compromised` says the retiring key
 * was, or may have been, in someone else's hands — and that is worth telling the people who
 * pinned it, because "my key changed" and "my key was stolen" call for different reactions from
 * them. It is carried by TOMBSTONING the retired key at every address it was bound to, rather
 * than by a flag on the rotation: a tombstone is a record in its own right, signed by the key
 * that took over, and it reaches a reader who only ever resolves the address.
 */
export type RotationSeverity = 'routine' | 'compromised';

/** An address's tombstones as the directory holds them. Removal records are append-only. */
export interface RemovalState {
  revision: number;
  removedBindings: { ed25519PublicKey: Uint8Array; removedAt: number }[];
}

/** One address's declaration that the key it just retired was compromised. */
export interface CompromiseDeclaration {
  address: string;
  /** A marshaled AddressRemovalRecord, signed by the key that took over. */
  removal: Uint8Array;
}

/**
 * A record as the directory holds it — everything the next one is built from.
 *
 * Every field the owner SIGNS belongs here, because the next record is rebuilt from this and
 * nothing else: one left out is not inherited, it is reset, and the reset is silent because the
 * new record is perfectly valid without it. `requireOnion` is the one that stings — an account
 * that required onion delivery would come back accepting direct stores, and no operator can put
 * it back, because it lives inside the owner self-signature. The operator-owned fields are the
 * exception: `relayHints` is carried in the routing credential and re-issued, which is why it is
 * absent here.
 */
export interface RecordState {
  version: number;
  revision: number;
  createdAt: number;
  expiresAt: number;
  verificationTier: number;
  requireOnion?: boolean;
  rotationChain: RotationEntryWire[];
  recoveryEd25519PublicKey?: Uint8Array;
}

/** One sibling address's current state, enough to build its own next record. */
export interface SiblingInput {
  address: string;
  record: RecordState;
  priorHistory: RotationEntryWire[];
  priorRemoval?: RemovalState;
}

/** One sibling address re-keyed: its new record and the history that explains it. */
export interface RotatedSibling {
  address: string;
  record: Uint8Array;
  history: Uint8Array;
}

export interface RotatedRecord {
  /** The new keypair, for the caller to persist once the directory has accepted the record. */
  next: IdentityKeyPair;
  /** The full record, marshaled and self-signed by the new key. */
  record: Uint8Array;
  selfSignature: Uint8Array;
  /** The chain entry this rotation added, for the history record. */
  entry: RotationEntryWire;
  /** The address's COMPLETE history, marshaled — what the capped chain on the record is not. */
  history: Uint8Array;
  /** The same handover applied to every address sharing this keypair. */
  siblings: RotatedSibling[];
  /**
   * One tombstone per address, when the retiring key is declared compromised.
   *
   * Every address the key answered to, because a key that is revoked at one name and live at
   * another has not been revoked. Empty for a routine re-key, and empty for an address whose
   * existing tombstone already covers the retired key.
   */
  compromise: CompromiseDeclaration[];
  rotatedAt: number;
}

/**
 * Build and sign a rotation, without publishing anything.
 *
 * Split from publishing on purpose: everything here is local and reversible, and a caller can
 * checkpoint between the two. Once the directory has the record the account's key HAS changed,
 * whatever happens next.
 *
 * The three signatures nest — the device attests the transition, the outgoing key consents to a
 * transition already naming that device, and the incoming key accepts the whole thing — so no
 * signature can be lifted onto a different handover.
 */
export async function signRotation(inputs: RotationInputs): Promise<RotatedRecord> {
  const { address, current, currentRecord, deviceCredential, device } = inputs;
  // An entry with no credential names no device, and every verifier on the network refuses one.
  // Caught here so the failure says what is actually wrong, rather than arriving as a rejected
  // publish after the ceremony has already asked for a password.
  if (deviceCredential.length === 0) {
    throw new Error('this device has no attestation from your domain, so it cannot authorize a re-key');
  }
  const next = await generateIdentityKeyPair();
  const rotatedAt = Math.floor(Date.now() / 1000);
  const credential = await decodeCredential(deviceCredential);

  /**
   * Re-key ONE address to `next`.
   *
   * The account and each of its shared aliases are the same job: each address has its own record,
   * its own revision and its own lineage, and each is signed separately — so an entry can never be
   * lifted from one address onto another, which is what binding the address inside the signature
   * buys.
   */
  const rekey = async (addr: string, state: RecordState) => {
    const nextRevision = state.revision + 1;
    const prior = state.rotationChain;
    // Chain to whatever history this record carries. An empty hash means the address's first
    // rotation, which is what tells a reader the history is complete.
    const prevSignatureHash = prior.length > 0
      ? await sha256(prior[prior.length - 1].signature!)
      : undefined;

    const entry: RotationEntryWire = {
      version: 1,
      address: addr,
      retiredEd25519PublicKey: current.ed25519Public,
      retiredX25519PublicKey: current.x25519Public,
      nextEd25519PublicKey: next.ed25519Public,
      nextX25519PublicKey: next.x25519Public,
      rotatedAt,
      nextRevision,
      prevSignatureHash,
      // The outgoing key authorises this one. A recovery-signed rotation would name the recovery
      // key here instead, and sign with it below.
      authorizingEd25519PublicKey: current.ed25519Public,
      deviceCredential: credential,
    };

    entry.deviceSignature = await device.sign(prefixed(ROTATION_DEVICE_CTX, await encodeRotationDeviceBytes(entry)));
    entry.signature = await sign(current.ed25519Private.slice(0, 32), prefixed(ROTATION_CTX, await encodeRotationConsentBytes(entry)));
    entry.nextSignature = await sign(next.ed25519Private.slice(0, 32), prefixed(ROTATION_ACCEPT_CTX, await encodeRotationAcceptBytes(entry)));

    // The chain carried ON the record is capped; the complete history travels separately. Dropping
    // the oldest links here is what keeps a record's size bounded as an account ages.
    const chain = [...prior, entry].slice(-MAX_ROTATION_CHAIN);

    // Everything the owner signs is inherited; only the keys, the revision and the chain change.
    // relayHints is operator-owned — excluded from the self-signature and re-issued with the
    // routing credential — so it is the one field rebuilt empty on purpose.
    const base = {
      version: state.version,
      address: addr,
      ed25519PublicKey: next.ed25519Public,
      x25519PublicKey: next.x25519Public,
      createdAt: state.createdAt,
      expiresAt: state.expiresAt,
      relayHints: [] as string[],
      verificationTier: state.verificationTier,
      requireOnion: state.requireOnion,
      revision: nextRevision,
      rotationChain: chain,
      recoveryEd25519PublicKey: state.recoveryEd25519PublicKey,
    };
    const selfSignature = await signSelfSignature(next.ed25519Private.slice(0, 32), await encodeIdentitySignableBytes(base));
    return { entry, selfSignature, record: await encodeIdentityRecord({ ...base, selfSignature }) };
  };

  const own = await rekey(address, currentRecord);
  const siblings: RotatedSibling[] = [];
  for (const sib of inputs.siblings ?? []) {
    const done = await rekey(sib.address, sib.record);
    siblings.push({
      address: sib.address,
      record: done.record,
      history: await encodeHistory(sib.address, [...sib.priorHistory, done.entry]),
    });
  }

  // A compromised re-key tombstones the retired key at every address it answered to. Signed by
  // the INCOMING key, which is what makes the declaration meaningful: a thief who had rotated the
  // address would hold that key instead, so this is a statement only the winner of the race can
  // make about the key they just replaced.
  const compromise: CompromiseDeclaration[] = [];
  if (inputs.severity === 'compromised') {
    for (const [addr, prior] of [
      [address, inputs.priorRemoval] as const,
      ...(inputs.siblings ?? []).map(s => [s.address, s.priorRemoval] as const),
    ]) {
      const removal = await signCompromise(addr, prior, current.ed25519Public, next, rotatedAt);
      if (removal) compromise.push({ address: addr, removal });
    }
  }

  return {
    next,
    record: own.record,
    selfSignature: own.selfSignature,
    entry: own.entry,
    history: await encodeHistory(address, [...inputs.priorHistory, own.entry]),
    siblings,
    compromise,
    rotatedAt,
  };
}

/**
 * Tombstone one address's retired key, extending whatever tombstones it already has.
 *
 * Removal records are append-only and are checked that way on write, so one rebuilt from nothing
 * would drop bindings somebody else retired and be refused by every node still holding them.
 * Returns null when the retired key is already covered, which makes the whole declaration safe to
 * repeat — a ceremony that resumes after publishing runs this again.
 */
async function signCompromise(
  address: string,
  prior: RemovalState | undefined,
  retired: Uint8Array,
  next: IdentityKeyPair,
  at: number,
): Promise<Uint8Array | null> {
  const bindings = prior?.removedBindings ?? [];
  if (bindings.some(b => sameBytes(b.ed25519PublicKey, retired))) return null;
  const base = {
    version: 1,
    domain: address.slice(address.indexOf('@') + 1),
    address,
    removedBindings: [...bindings, { ed25519PublicKey: retired, removedAt: at }],
    revision: (prior?.revision ?? 0) + 1,
    createdAt: at,
  };
  const selfSignature = await sign(
    next.ed25519Private.slice(0, 32),
    removalSigningBytes(await encodeRemovalSignableBytes(base)),
  );
  return encodeRemovalRecord({ ...base, selfSignature });
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * Hand the outgoing generation to the retired-key ring, then swap in the new one.
 *
 * Retaining FIRST is not a style choice. It is the only moment both generations exist on this
 * device, and a keystore re-wrapped before the old keys were kept would leave every message and
 * storage blob written under them permanently unreadable — the relay holds only ciphertext and
 * cannot help.
 */
export async function retainThenSwap(
  address: string,
  outgoing: IdentityKeyPair,
  outgoingAliasRoot: CryptoKey | undefined,
  rotatedAt: number,
  swap: () => Promise<void>,
): Promise<void> {
  await retainRetiredFromKeyPair(address, outgoing, outgoingAliasRoot, rotatedAt);
  await swap();
}

/** Prefix signable bytes with their domain-separation context, ready to sign. */
function prefixed(ctx: Uint8Array, body: Uint8Array): Uint8Array {
  const out = new Uint8Array(ctx.length + body.length);
  out.set(ctx, 0);
  out.set(body, ctx.length);
  return out;
}

/**
 * Decode a marshaled Credential into the shape the entry encoder expects.
 *
 * The credential travels as opaque bytes everywhere else — this client never inspects one — but
 * it has to nest inside the entry's own protobuf, so it is decoded here and nowhere else.
 */
async function decodeCredential(marshaled: Uint8Array): Promise<unknown> {
  const { decodeCredential: decode } = await import('./protobuf');
  return decode(marshaled);
}

/**
 * SHA-256 over bytes, via the BufferSource helper the rest of this package uses.
 *
 * Exists because a bare Uint8Array is not assignable to BufferSource under this tsconfig — see
 * bytes.ts for why.
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data)));
}

/** Whether this deployment can publish a rotation at all. */
export function rotationSupported(): boolean {
  return typeof deployment.publishRotation === 'function';
}

// --- The ceremony ---------------------------------------------------------------------------

/**
 * Everything the ceremony does that is not building and signing the record.
 *
 * Injected rather than imported so the ORDER can be tested — which matters more than any single
 * step here, because several are irreversible on their own and a wrong sequence produces failures
 * a user cannot recover from. A test that drives this with recorders asserts the one property
 * that is invisible in the code: what happens when a step fails half-way.
 */
export interface RotationSteps {
  /** Persist how far the ceremony has got, so an interruption can be resumed rather than lost. */
  saveCheckpoint(cp: RotationCheckpoint): Promise<void>;
  clearCheckpoint(address: string): Promise<void>;
  /**
   * Record which generation of the account key derived each thing derived FROM it, while the
   * outgoing key is still the account's. Optional: a deployment that derives nothing from the
   * account key has nothing to record.
   *
   * First, and before anything is staged, because it is the one step whose whole value is being
   * done while the old key is still current — and a failure here costs nothing, since nothing
   * has happened yet.
   */
  stampGenerations?(): Promise<void>;
  /**
   * Publish the tombstones declaring the retired key stolen. Optional.
   *
   * After the rotated records, because a tombstone signed by the incoming key is only verifiable
   * against a record that names that key — a node still holding the old one refuses it.
   */
  declareStolen?(declarations: CompromiseDeclaration[]): Promise<void>;
  /**
   * Read the account's mail filter, sealed to the OUTGOING key. Optional.
   *
   * The block list is the one piece of mailbox state a re-key cannot carry by itself: the relay
   * holds it sealed to the owner and cannot re-seal what it cannot read, so it is dropped with
   * the old key and put back by the client. Read before anything is published, while the old key
   * still opens it.
   */
  readMailFilter?(): Promise<FilterList | null>;
  /** Put the filter back, sealed to the new key, once that key owns the mailbox. */
  writeMailFilter?(list: FilterList, next: IdentityKeyPair): Promise<void>;
  /**
   * Whether the directory has already accepted this rotation. Optional.
   *
   * Asked only after a publish FAILED, because a failed publish is ambiguous in the one way that
   * matters: the request may have landed and the answer been lost. Treating that as "did not
   * happen" would discard the checkpoint for a rotation the network has already taken, leaving
   * the account re-keyed with the owner holding a key nobody accepts.
   */
  published?(address: string, ed25519Public: Uint8Array): Promise<boolean>;
  /** Hold the new keypair under a staging name, before anything commits to it. */
  stageKeys(address: string, next: IdentityKeyPair): Promise<void>;
  /**
   * Publish the rotated record, the history that explains it, and every sibling address moving
   * to the same key. One call, because a rotation that re-keys some of an account's addresses
   * and not the rest leaves the retired key live on the mailbox.
   */
  publish(record: Uint8Array, history: Uint8Array, siblings: RotatedSibling[]): Promise<void>;
  /** Ask each home relay to re-key the mailbox to the new owner key. */
  renameMailbox(next: IdentityKeyPair): Promise<void>;
  /** Withdraw the push registration belonging to the OLD mailbox key. */
  tearDownPush(): Promise<void>;
  /** Keep the outgoing generation, so what it sealed stays readable. */
  retainRetired(address: string, outgoing: IdentityKeyPair, aliasRoot: CryptoKey | undefined, at: number): Promise<void>;
  /** Re-wrap the real keystore around the new keypair, replacing the staged copy. */
  commitKeys(address: string, next: IdentityKeyPair): Promise<void>;
  /** Sign back in to both services with the new key; the old sessions are bound to the old one. */
  reestablishSessions(address: string, next: IdentityKeyPair): Promise<void>;
  /** Drop this account from shared device unlock, whose stored key opens the old bundle. */
  detachSharedUnlock(address: string): Promise<void>;
  /**
   * Re-seal personal storage to the new key. Optional.
   *
   * LAST, and failures are swallowed by the caller. The device that just rotated can read all of
   * it either way — the retired generation is kept for exactly that — so what this buys is that
   * devices paired LATER can read it too. Worth doing here, where both generations are loaded,
   * and not worth failing a completed rotation over.
   */
  resealStorage?(next: IdentityKeyPair): Promise<void>;
}

/** Named so a caller can report progress without knowing the sequence. */
export type RotationStage =
  | 'signing' | 'publishing' | 'rekeying-mailbox' | 'swapping-keys' | 'restoring-session' | 'done';

/**
 * Re-key an account, from a signed record through to a working session on the new key.
 *
 * The sequence, and why each step sits where it does:
 *
 *  0. STAMP anything derived from the account key with the generation that derived it, while that
 *     generation is still current. Afterwards nothing on this device can say which one it was.
 *  1. STAGE the new keypair and CHECKPOINT — both local, both before any network call. A ceremony
 *     interrupted after this point can be finished; one interrupted before it has changed nothing.
 *  2. PUBLISH. This is the point of no return: from here the directory says the account's key is
 *     the new one, whatever happens next. Everything after this is recovery, not choice.
 *  3. RE-KEY THE MAILBOX on the relays. After publishing, because a relay derives the previous
 *     mailbox key from the record's own rotation chain and cannot act until it has the record.
 *  4. TEAR DOWN PUSH before the keystore swap, because the registration's identifier derives from
 *     the old mailbox key and becomes unreachable the moment the local keys change.
 *  5. RETAIN the outgoing generation before swapping it out — the only moment both exist here.
 *  6. COMMIT the keystore, then re-establish sessions and detach shared unlock, whose stored key
 *     opens a bundle that no longer exists.
 *
 * A failure after step 2 leaves the checkpoint in place and rethrows. That is deliberate: the
 * account IS re-keyed, so the remedy is to finish, and silently swallowing the error would leave
 * someone signed in with keys the network has stopped accepting. A failure OF step 2 is the
 * ambiguous one — the publish may have landed and the answer been lost — so the directory is
 * asked rather than guessed at.
 */
export async function runRotation(
  inputs: RotationInputs,
  steps: RotationSteps,
  onStage?: (stage: RotationStage) => void,
): Promise<RotatedRecord> {
  const { address, current, outgoingAliasRoot } = inputs;
  const stage = (s: RotationStage) => onStage?.(s);

  // While the outgoing key is still the account's — see RotationSteps.stampGenerations.
  await steps.stampGenerations?.();

  stage('signing');
  const signed = await signRotation(inputs);
  // Read while the old key still opens it, and kept on the checkpoint so a ceremony that resumes
  // after the swap can still put it back.
  const mailFilter = (await steps.readMailFilter?.()) ?? undefined;
  const checkpoint: RotationCheckpoint = {
    address,
    phase: 'signed',
    startedAt: signed.rotatedAt,
    oldEd25519Public: current.ed25519Public,
    newEd25519Public: signed.next.ed25519Public,
    mailFilter,
    compromise: signed.compromise.length > 0 ? signed.compromise : undefined,
  };
  // Staged and checkpointed BEFORE the first network call. Nothing here is visible to anyone
  // else yet, so an interruption at this point costs only the work.
  await steps.stageKeys(address, signed.next);
  await steps.saveCheckpoint(checkpoint);

  stage('publishing');
  try {
    await steps.publish(signed.record, signed.history, signed.siblings);
  } catch (err) {
    // A publish that reports failure may still have landed — the request reached the directory
    // and the answer was lost. Ask, because the two cases need opposite handling: one is a
    // rotation to abandon, the other is a rotation to finish.
    if (!(await steps.published?.(address, signed.next.ed25519Public))) throw err;
  }
  // From here the account's key HAS changed as far as the network is concerned. Every later
  // failure is something to finish, never something to abandon.
  await steps.saveCheckpoint({ ...checkpoint, phase: 'published' });

  await finishRotation(
    address, signed.next, current, outgoingAliasRoot, signed.rotatedAt,
    mailFilter, signed.compromise, steps, stage,
  );
  return signed;
}

/**
 * Complete a rotation whose record is already published.
 *
 * Shared by the first attempt and by resume, because after publishing they are the same job: the
 * directory has moved on, and the device has to catch up.
 */
async function finishRotation(
  address: string,
  next: IdentityKeyPair,
  outgoing: IdentityKeyPair,
  outgoingAliasRoot: CryptoKey | undefined,
  rotatedAt: number,
  mailFilter: FilterList | undefined,
  compromise: CompromiseDeclaration[] | undefined,
  steps: RotationSteps,
  stage: (s: RotationStage) => void,
): Promise<void> {
  // First of the post-publish steps, because it is the one with a deadline: until it lands, every
  // contact who resolves the address is told the key merely changed. Safe to repeat — a tombstone
  // that already covers the retired key is not rebuilt.
  if (compromise?.length) await steps.declareStolen?.(compromise);

  stage('rekeying-mailbox');
  await steps.renameMailbox(next);
  await steps.saveCheckpoint({
    address, phase: 'rekeyed', startedAt: rotatedAt,
    oldEd25519Public: outgoing.ed25519Public, newEd25519Public: next.ed25519Public,
  });

  stage('swapping-keys');
  // Push first: its scope comes from the old mailbox key, so after the swap there is nothing left
  // to identify the registration by, and it would linger as a live endpoint nobody owns.
  await steps.tearDownPush();
  // Then keep the outgoing generation, while it is still loaded. A keystore re-wrapped before
  // this would leave everything those keys sealed permanently unreadable.
  await steps.retainRetired(address, outgoing, outgoingAliasRoot, rotatedAt);
  await steps.commitKeys(address, next);

  stage('restoring-session');
  await steps.reestablishSessions(address, next);
  // The block list goes back now that the new key owns the mailbox. After the session, because
  // the relay authenticates this write against the record it can resolve — which is the new one.
  if (mailFilter) await steps.writeMailFilter?.(mailFilter, next);
  // Shared device unlock stores a key that opens the OLD bundle, so after the re-wrap it opens
  // nothing. Detaching says so, rather than leaving the account silently absent from the list.
  await steps.detachSharedUnlock(address);

  // Everything still sealed to the outgoing key, moved onto the new one. Deliberately last and
  // deliberately forgiving: this device reads it either way through the retired ring, so a
  // failure costs devices paired later rather than the rotation, and stopping here would leave a
  // checkpoint for a ceremony that is otherwise complete.
  try {
    await steps.resealStorage?.(next);
  } catch (err) {
    console.warn('personal storage was not re-sealed to the new key', err);
  }

  await steps.clearCheckpoint(address);
  stage('done');
}

/**
 * Finish a rotation that was interrupted after publishing.
 *
 * A checkpoint at `signed` is discarded instead: nothing was published, so the staged key was
 * never the account's and resuming would publish a rotation the user may have abandoned. From
 * `published` onward there is no choice — the directory has already moved.
 */
export async function resumeRotation(
  cp: RotationCheckpoint,
  next: IdentityKeyPair,
  outgoing: IdentityKeyPair,
  outgoingAliasRoot: CryptoKey | undefined,
  steps: RotationSteps,
  onStage?: (stage: RotationStage) => void,
): Promise<void> {
  if (cp.phase === 'signed') {
    // The directory decides. A ceremony that stopped here usually published nothing, but one
    // whose publish failed after landing looks identical from this device — and discarding that
    // one would leave the account re-keyed with nobody finishing the job.
    if (!(await steps.published?.(cp.address, next.ed25519Public))) {
      await steps.clearCheckpoint(cp.address);
      return;
    }
  }
  await finishRotation(
    cp.address, next, outgoing, outgoingAliasRoot, cp.startedAt,
    cp.mailFilter, cp.compromise, steps, onStage ?? (() => {}),
  );
}

/** Build the complete history record for one address. */
async function encodeHistory(address: string, chain: RotationEntryWire[]): Promise<Uint8Array> {
  const { encodeAddressHistory } = await import('./protobuf');
  // The history is COMPLETE, unlike the capped chain on the record — it is what a reader consults
  // when their pinned key fell outside that window, so a truncated one would send them nowhere.
  return encodeAddressHistory({
    version: 1,
    domain: address.slice(address.indexOf('@') + 1),
    address,
    chain,
  });
}
