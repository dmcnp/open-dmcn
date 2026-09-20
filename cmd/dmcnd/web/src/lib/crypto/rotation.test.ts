import { describe, it, expect } from 'vitest';
import { bufferSource } from './bytes';
import { MAX_ROTATION_CHAIN } from './verifyRotation';
import { encodeRotationConsentBytes, encodeRotationDeviceBytes, encodeRotationAcceptBytes } from './protobuf';

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

const entry = {
  version: 1,
  address: 'alice@dmcn.email',
  retiredEd25519PublicKey: fill(32, 0x01),
  retiredX25519PublicKey: fill(32, 0x02),
  nextEd25519PublicKey: fill(32, 0x03),
  nextX25519PublicKey: fill(32, 0x04),
  rotatedAt: 1_700_000_000,
  nextRevision: 2,
  authorizingEd25519PublicKey: fill(32, 0x01),
};

// The cap has to match Go's identity.MaxRotationChain exactly. A record carrying more entries is
// refused outright, so a client that drifted above it would publish records nothing on the network
// accepts — and the failure would arrive only after the user had already re-keyed.
describe('rotation chain cap', () => {
  it('matches the limit the network enforces', () => {
    expect(MAX_ROTATION_CHAIN).toBe(8);
  });
});

// The three signatures NEST, each covering the ones before it. That ordering is what stops a
// signature being lifted from one transition onto another, and it is invisible unless asserted:
// signing in the wrong order still produces a well-formed entry, just one every relay rejects.
describe('rotation entry signing extents', () => {
  it('consent covers the device attestation', async () => {
    const device = await encodeRotationDeviceBytes(entry);
    const consent = await encodeRotationConsentBytes({ ...entry, deviceSignature: fill(64, 0x0e) });
    expect(hex(consent).startsWith(hex(device))).toBe(true);
    expect(consent.length).toBeGreaterThan(device.length);
  });

  it('acceptance covers the consent', async () => {
    const withDevice = { ...entry, deviceSignature: fill(64, 0x0e) };
    const consent = await encodeRotationConsentBytes(withDevice);
    const accept = await encodeRotationAcceptBytes({ ...withDevice, signature: fill(64, 0x0f) });
    expect(hex(accept).startsWith(hex(consent))).toBe(true);
    expect(accept.length).toBeGreaterThan(consent.length);
  });

  it('a device signature added later changes what consent covers', async () => {
    // The point of the nesting: an outgoing key cannot consent to a handover and have a different
    // device attestation swapped in afterwards.
    const a = await encodeRotationConsentBytes({ ...entry, deviceSignature: fill(64, 0x0e) });
    const b = await encodeRotationConsentBytes({ ...entry, deviceSignature: fill(64, 0x11) });
    expect(hex(a)).not.toBe(hex(b));
  });
});

import { runRotation, resumeRotation, type RotationCheckpoint, type RotationSteps } from './rotation';
import { generateIdentityKeyPair, type IdentityKeyPair } from './keys';

// A recorder for the ceremony's side effects. The ORDER is what these tests are about: several
// steps are irreversible on their own, and a wrong sequence produces failures a user cannot
// recover from — a keystore swapped before the old keys were kept, a push scope torn down after
// its identifier became unreachable, a record published before anything was checkpointed.
function recorder(fail?: { at: keyof RotationSteps; err?: Error }, opts?: { alreadyPublished?: boolean }) {
  const order: string[] = [];
  const checkpoints: RotationCheckpoint[] = [];
  const step = <T>(name: keyof RotationSteps, run?: () => T) => async (...args: unknown[]): Promise<T> => {
    order.push(name);
    if (fail?.at === name) throw fail.err ?? new Error(`${name} failed`);
    if (name === 'saveCheckpoint') checkpoints.push(args[0] as RotationCheckpoint);
    return run?.() as T;
  };
  const steps: RotationSteps = {
    saveCheckpoint: step('saveCheckpoint'),
    clearCheckpoint: step('clearCheckpoint'),
    stampGenerations: step('stampGenerations'),
    stageKeys: step('stageKeys'),
    readMailFilter: step('readMailFilter', () => ({ mode: 'deny', domains: [], senders: ['spam@dmcn.email'] })),
    writeMailFilter: step('writeMailFilter'),
    publish: step('publish'),
    declareStolen: step('declareStolen'),
    published: step('published', () => !!opts?.alreadyPublished),
    renameMailbox: step('renameMailbox'),
    tearDownPush: step('tearDownPush'),
    retainRetired: step('retainRetired'),
    commitKeys: step('commitKeys'),
    reestablishSessions: step('reestablishSessions'),
    detachSharedUnlock: step('detachSharedUnlock'),
    resealStorage: step('resealStorage'),
  };
  return { steps, order, checkpoints };
}

/**
 * A Credential carrying only its SUBJECT, hand-encoded (field 2, bytes).
 *
 * The chain walk reads exactly one field of the credential — who the device is — and verifying
 * the credential's own issuer chain is an admission-time question asked elsewhere. So a real one
 * would add nothing here but a domain authority to stand up.
 */
function credentialFor(subject: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + subject.length);
  out[0] = 0x12;             // field 2, wire type 2
  out[1] = subject.length;
  out.set(subject, 2);
  return out;
}

// A record as the directory holds it. Spelled once: RecordState carries every field the owner
// signs, and a test that filled it in by hand would stop compiling each time one is added — which
// is exactly the reminder that matters, but only needs answering in one place.
const held = (revision: number, createdAt: number): RecordState =>
  ({ version: 1, revision, createdAt, expiresAt: 0, verificationTier: 0, rotationChain: [] });

async function rotationInputs(address: string) {
  const current = await generateIdentityKeyPair();
  // The device signer is an input, so the ordering is exercisable without a browser.
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
  const devicePublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const device = {
    publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)),
    sign: async (data: Uint8Array) =>
      new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, bufferSource(data))),
  };
  return {
    address,
    device,
    current,
    currentRecord: held(1, 1_700_000_000),
    deviceCredential: credentialFor(devicePublic),
    priorHistory: [],
  };
}

describe('the rotation ceremony', () => {
  it('stages and checkpoints BEFORE anything is published', async () => {
    // Before this point nothing is visible to anyone else, so an interruption costs only the
    // work. After it, the ceremony can be finished rather than abandoned.
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order.indexOf('stageKeys')).toBeLessThan(order.indexOf('publish'));
    expect(order.indexOf('saveCheckpoint')).toBeLessThan(order.indexOf('publish'));
  });

  it('re-keys the mailbox only after the record is published', async () => {
    // A relay derives the PREVIOUS mailbox key from the record's own rotation chain, so it cannot
    // act until it has the record.
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order.indexOf('publish')).toBeLessThan(order.indexOf('renameMailbox'));
  });

  it('tears down push and keeps the old keys BEFORE swapping the keystore', async () => {
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    // The push scope's identifier derives from the old mailbox key: after the swap there is
    // nothing left to identify the registration by.
    expect(order.indexOf('tearDownPush')).toBeLessThan(order.indexOf('commitKeys'));
    // And this is the only moment both generations exist on the device. A keystore re-wrapped
    // first would leave everything the old keys sealed permanently unreadable.
    expect(order.indexOf('retainRetired')).toBeLessThan(order.indexOf('commitKeys'));
  });

  it('clears the checkpoint only at the very end', async () => {
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order[order.length - 1]).toBe('clearCheckpoint');
  });

  it('leaves the checkpoint in place when a step after publishing fails', async () => {
    // The account IS re-keyed by then, so the remedy is to finish. Swallowing the error would
    // leave someone signed in with keys the network has stopped accepting.
    const { steps, order } = recorder({ at: 'commitKeys' });
    await expect(runRotation(await rotationInputs('alice@dmcn.email'), steps)).rejects.toThrow();
    expect(order).not.toContain('clearCheckpoint');
    expect(order).toContain('publish');
  });

  it('never publishes when signing cannot complete', async () => {
    const { steps, order } = recorder({ at: 'stageKeys' });
    await expect(runRotation(await rotationInputs('alice@dmcn.email'), steps)).rejects.toThrow();
    expect(order).not.toContain('publish');
  });
});

describe('resuming an interrupted rotation', () => {
  const cp = (phase: RotationCheckpoint['phase']): RotationCheckpoint => ({
    address: 'alice@dmcn.email',
    phase,
    startedAt: 1_700_000_000,
    oldEd25519Public: new Uint8Array(32),
    newEd25519Public: new Uint8Array(32).fill(1),
  });

  let next: IdentityKeyPair;
  let outgoing: IdentityKeyPair;

  it('discards a ceremony that never published', async () => {
    // Nothing reached the directory, so the staged key was never the account's. Resuming would
    // publish a rotation the user may have deliberately abandoned.
    next = await generateIdentityKeyPair();
    outgoing = await generateIdentityKeyPair();
    const { steps, order } = recorder();
    await resumeRotation(cp('signed'), next, outgoing, undefined, steps);
    // The directory is asked first: a publish that failed AFTER landing looks identical from
    // here, and discarding that one would leave the account re-keyed with nobody finishing.
    expect(order).toEqual(['published', 'clearCheckpoint']);
  });

  it('finishes one that did publish, in the same order as a first attempt', async () => {
    const { steps, order } = recorder();
    await resumeRotation(cp('published'), next, outgoing, undefined, steps);
    expect(order.indexOf('renameMailbox')).toBeLessThan(order.indexOf('tearDownPush'));
    expect(order.indexOf('retainRetired')).toBeLessThan(order.indexOf('commitKeys'));
    expect(order[order.length - 1]).toBe('clearCheckpoint');
  });

  it('skips nothing it already did, because every step is safe to repeat', async () => {
    // A rename that already happened is a no-op at the relay, a retained generation is already
    // kept, and a keystore re-wrap is idempotent. Making resume conditional on how far it got
    // would add branches whose only job is to skip work that costs nothing.
    const { steps, order } = recorder();
    await resumeRotation(cp('rekeyed'), next, outgoing, undefined, steps);
    expect(order).toContain('renameMailbox');
    expect(order).toContain('commitKeys');
  });
});

import { signRotation, type RecordState } from './rotation';
import { decodeAddressRemoval, decodeIdentityRecord } from './protobuf';

// Shared aliases are the account's own keypair under another name. A rotation that re-keyed the
// account and left an alias behind would report success while the retired key still opened this
// mailbox under that name — so the siblings move in the same ceremony, to the same key, each with
// its own record and its own lineage.
describe('rotating the addresses that share a keypair', () => {
  it('re-keys every sibling to the same new keys, each on its own record', async () => {
    const inputs = await rotationInputs('alice@dmcn.email');
    const signed = await signRotation({
      ...inputs,
      siblings: [
        { address: 'sales@dmcn.email', record: held(3, 1_600_000_000), priorHistory: [] },
        { address: 'hi@dmcn.email', record: held(1, 1_650_000_000), priorHistory: [] },
      ],
    });

    expect(signed.siblings.map(s => s.address)).toEqual(['sales@dmcn.email', 'hi@dmcn.email']);
    for (const sib of signed.siblings) {
      const rec = await decodeIdentityRecord(sib.record);
      expect(rec.address).toBe(sib.address);
      // The SAME key, because two keys would mean two mailboxes for addresses that share one.
      expect(hex(rec.ed25519PublicKey)).toBe(hex(signed.next.ed25519Public));
      expect(hex(rec.x25519PublicKey)).toBe(hex(signed.next.x25519Public));
      // Its own lineage: the entry names the sibling's address, so it cannot be lifted onto
      // another address, and its own revision rather than the account's.
      const entry = rec.rotationChain[rec.rotationChain.length - 1];
      expect(entry.address).toBe(sib.address);
      expect(hex(entry.retiredEd25519PublicKey)).toBe(hex(inputs.current.ed25519Public));
      expect(sib.history.length).toBeGreaterThan(0);
    }
    // Each carries the revision that address was on. A sibling signed at the ACCOUNT's revision
    // would be refused as stale or accepted as a leap, depending on which address was further
    // along — so they have to be tracked per address. (uint64 arrives as a Long.)
    expect(Number((await decodeIdentityRecord(signed.siblings[0].record)).revision)).toBe(4);
    expect(Number((await decodeIdentityRecord(signed.siblings[1].record)).revision)).toBe(2);
  });

  it('publishes the account and its siblings in one call', async () => {
    // Split across calls, a failure between them would leave the account re-keyed with an alias
    // still on the old key — the exact state the sibling rule exists to prevent.
    const published: unknown[][] = [];
    const { steps } = recorder();
    steps.publish = async (...args: unknown[]) => { published.push(args); };
    await runRotation({
      ...(await rotationInputs('alice@dmcn.email')),
      siblings: [{ address: 'sales@dmcn.email', record: held(1, 1_600_000_000), priorHistory: [] }],
    }, steps);
    expect(published).toHaveLength(1);
    expect((published[0][2] as { address: string }[]).map(s => s.address)).toEqual(['sales@dmcn.email']);
  });
});

import { encodeIdentityRecord } from './protobuf';

// The chain a device reads back from the directory is RE-ENCODED into the next record, entries and
// all. Every one of those entries is already signed, so if re-encoding changed a single byte the
// signatures would stop verifying and the network would refuse the record — with the user's local
// keystore already moved to the new key. Nothing about that failure would point here.
describe('a chain that arrives from the directory', () => {
  it('re-encodes byte-identically', async () => {
    const first = await signRotation(await rotationInputs('alice@dmcn.email'));
    const dec = await decodeIdentityRecord(first.record);

    const again = await encodeIdentityRecord({
      version: Number(dec.version),
      address: dec.address,
      ed25519PublicKey: dec.ed25519PublicKey,
      x25519PublicKey: dec.x25519PublicKey,
      createdAt: Number(dec.createdAt),
      expiresAt: Number(dec.expiresAt ?? 0),
      relayHints: dec.relayHints ?? [],
      verificationTier: Number(dec.verificationTier ?? 0),
      revision: Number(dec.revision),
      rotationChain: dec.rotationChain,
      selfSignature: dec.selfSignature,
    });
    expect(hex(again)).toBe(hex(first.record));
  });
});

// Two things about a re-key are invisible until someone runs into them months later: the block
// list the relay cannot re-seal for you, and a publish whose answer was lost on the way back.
describe('what a rotation carries across, and what it asks about', () => {
  it('reads the mail filter before publishing and puts it back after the new session', async () => {
    // Before, because the relay holds it sealed to the OLD key and the re-key drops it. After the
    // session, because the write authenticates against the record the relay can resolve — which
    // by then is the new one.
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order.indexOf('readMailFilter')).toBeLessThan(order.indexOf('publish'));
    expect(order.indexOf('reestablishSessions')).toBeLessThan(order.indexOf('writeMailFilter'));
  });

  it('carries the filter on the checkpoint, so a resumed ceremony can still restore it', async () => {
    // By the time a resume runs, the old key is retired and the relay has already let the list
    // go — there is nowhere left to read it from.
    const { steps, checkpoints } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(checkpoints[0].mailFilter?.senders).toEqual(['spam@dmcn.email']);
  });

  it('records the generation before the key changes', async () => {
    // Anything derived from the account key has to be marked while that key is still the
    // account's; afterwards this device can no longer say which generation it was.
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order[0]).toBe('stampGenerations');
  });

  it('finishes a rotation whose publish landed but reported failure', async () => {
    // The ambiguous case. Treating it as "did not happen" would discard the checkpoint for a
    // rotation the network has already taken — the account re-keyed, the owner holding a key
    // nobody accepts, and nothing left pointing at the way out.
    const { steps, order } = recorder({ at: 'publish' }, { alreadyPublished: true });
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order).toContain('published');
    expect(order[order.length - 1]).toBe('clearCheckpoint');
  });

  it('rethrows a publish that really did fail', async () => {
    const { steps, order } = recorder({ at: 'publish' }, { alreadyPublished: false });
    await expect(runRotation(await rotationInputs('alice@dmcn.email'), steps)).rejects.toThrow();
    expect(order).not.toContain('renameMailbox');
    expect(order).not.toContain('clearCheckpoint');
  });
});

// "My key changed" and "my key was stolen" ask different things of everyone who saved that key.
// The second is carried by tombstoning the retired key at every address it answered to, signed by
// the key that took over — which is the statement only the winner of the race can make.
describe('declaring a retired key stolen', () => {
  const removalFor = async (severity: 'routine' | 'compromised', siblings: string[] = []) => {
    const base = await rotationInputs('alice@dmcn.email');
    return signRotation({
      ...base,
      severity,
      siblings: siblings.map(address => ({
        address, record: held(1, 1_600_000_000), priorHistory: [],
      })),
    });
  };

  it('publishes nothing extra for a routine re-key', async () => {
    expect((await removalFor('routine')).compromise).toEqual([]);
  });

  it('tombstones every address the key answered to', async () => {
    // A key revoked at one name and live at another has not been revoked.
    const signed = await removalFor('compromised', ['sales@dmcn.email']);
    expect(signed.compromise.map(c => c.address)).toEqual(['alice@dmcn.email', 'sales@dmcn.email']);
  });

  it('extends existing tombstones instead of replacing them', async () => {
    // Removal records are append-only and checked that way on write, so one rebuilt from nothing
    // would drop a binding somebody else retired and be refused everywhere that still holds it.
    const earlier = fill(32, 0x07);
    const base = await rotationInputs('alice@dmcn.email');
    const signed = await signRotation({
      ...base,
      severity: 'compromised',
      priorRemoval: { revision: 3, removedBindings: [{ ed25519PublicKey: earlier, removedAt: 1_600_000_000 }] },
    });
    const rm = await decodeAddressRemoval(signed.compromise[0].removal);
    expect(Number(rm.revision)).toBe(4);
    expect(rm.removedBindings.map((b: { ed25519PublicKey: Uint8Array }) => hex(b.ed25519PublicKey)))
      .toEqual([hex(earlier), hex(base.current.ed25519Public)]);
  });

  it('says nothing twice when the key is already tombstoned', async () => {
    // Which is what makes the whole declaration safe to repeat: a ceremony that resumes after
    // publishing runs it again.
    const base = await rotationInputs('alice@dmcn.email');
    const signed = await signRotation({
      ...base,
      severity: 'compromised',
      priorRemoval: {
        revision: 1,
        removedBindings: [{ ed25519PublicKey: base.current.ed25519Public, removedAt: 1_600_000_000 }],
      },
    });
    expect(signed.compromise).toEqual([]);
  });

  it('declares before the mailbox moves, and carries it on the checkpoint', async () => {
    // Before, because until it lands every contact resolving the address is told only that the
    // key changed; on the checkpoint, because a resumed ceremony cannot rebuild it.
    const { steps, order, checkpoints } = recorder();
    await runRotation({ ...(await rotationInputs('alice@dmcn.email')), severity: 'compromised' }, steps);
    expect(order.indexOf('publish')).toBeLessThan(order.indexOf('declareStolen'));
    expect(order.indexOf('declareStolen')).toBeLessThan(order.indexOf('renameMailbox'));
    expect(checkpoints[0].compromise).toHaveLength(1);
  });
});

// Personal storage is sealed to the key that wrote it, and the relay cannot re-seal what it
// cannot read. So the device that rotated is the only party that can move it onto the new key —
// and it can only do that while both generations are loaded.
describe('re-sealing what the old key sealed', () => {
  it('runs last, once the new key is the account key', async () => {
    const { steps, order } = recorder();
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order.indexOf('commitKeys')).toBeLessThan(order.indexOf('resealStorage'));
    expect(order.indexOf('reestablishSessions')).toBeLessThan(order.indexOf('resealStorage'));
  });

  it('does not fail a completed rotation', async () => {
    // This device reads everything either way through the retired ring, so what a failure costs
    // is devices paired LATER — not a reason to leave a checkpoint for a ceremony that is done.
    const { steps, order } = recorder({ at: 'resealStorage' });
    await runRotation(await rotationInputs('alice@dmcn.email'), steps);
    expect(order[order.length - 1]).toBe('clearCheckpoint');
  });
});

// A rotation rebuilds the record from nothing, so every field the OWNER signs has to be carried
// across on purpose. A field left out is not inherited — it is reset, on a record that verifies
// perfectly. require_onion is the one that stings: it lives inside the self-signature, so no
// operator can put it back, and an account that required onion delivery would quietly start
// accepting direct stores again. relayHints is the deliberate exception, operator-owned and
// re-issued with the routing credential.
describe('what the new record inherits', () => {
  it('carries every owner-signed field across the re-key', async () => {
    const signed = await signRotation({
      ...(await rotationInputs('alice@dmcn.email')),
      currentRecord: {
        version: 1,
        revision: 4,
        createdAt: 1_600_000_000,
        expiresAt: 1_900_000_000,
        verificationTier: 2,
        requireOnion: true,
        rotationChain: [],
      },
    });
    const rec = await decodeIdentityRecord(signed.record);
    expect(rec.requireOnion).toBe(true);
    expect(Number(rec.expiresAt)).toBe(1_900_000_000);
    expect(rec.verificationTier).toBe(2);
    expect(Number(rec.createdAt)).toBe(1_600_000_000);
    expect(Number(rec.revision)).toBe(5);
  });
});
