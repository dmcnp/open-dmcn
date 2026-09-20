import { describe, it, expect, vi } from 'vitest';
import { signRotation, type RotationInputs, type RotatedRecord } from '../crypto/rotation';
import { decodeAddressHistory, decodeIdentityRecord, encodeIdentityRecord, encodeIdentitySignableBytes,
  encodeRotationConsentBytes, encodeRotationDeviceBytes, encodeRotationAcceptBytes } from '../crypto/protobuf';
import { signSelfSignature, rotationConsentSigningBytes, rotationDeviceSigningBytes, rotationAcceptSigningBytes } from '../crypto/identity';
import { sign } from '../crypto/sign';
import { decodeCredential } from '../crypto/protobuf';
import { generateIdentityKeyPair, toBase64, type IdentityKeyPair } from '../crypto/keys';
import { bufferSource } from '../crypto/bytes';
import { explainKeyChange } from './lineage';
import type { IdentityRecordResponse } from '../api/client';

// The client works out for ITSELF what happened to a key it pinned. The fleet is the party a pin
// exists to catch, so an explanation that fleet merely asserted would be no counterweight — which
// is why the negative cases here matter as much as the positive ones: a chain that does not hold
// up has to read as "nothing explains this", never as a softer answer.

/** A Credential carrying only its SUBJECT (field 2), which is all a chain walk reads. */
function credentialFor(subject: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + subject.length);
  out[0] = 0x12;
  out[1] = subject.length;
  out.set(subject, 2);
  return out;
}

async function inputs(address: string, current: IdentityKeyPair, revision: number, priorHistory: RotationInputs['priorHistory'] = []): Promise<RotationInputs> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
  const devicePublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return {
    address,
    device: {
      publicKey: devicePublic,
      sign: async (data: Uint8Array) =>
        new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, bufferSource(data))),
    },
    current,
    currentRecord: { version: 1, revision, createdAt: 1_700_000_000, expiresAt: 0, verificationTier: 0, rotationChain: [] },
    deviceCredential: credentialFor(devicePublic),
    priorHistory,
  };
}

const served = (signed: RotatedRecord, extra: Partial<IdentityRecordResponse> = {}): IdentityRecordResponse => ({
  address: 'alice@dmcn.email',
  record: toBase64(signed.record),
  history: toBase64(signed.history),
  ...extra,
});

describe('explaining a key that no longer matches the pin', () => {
  const ADDR = 'alice@dmcn.email';

  it('reports a signed handover as a replacement, dated', async () => {
    const outgoing = await generateIdentityKeyPair();
    const signed = await signRotation(await inputs(ADDR, outgoing, 1));
    const change = await explainKeyChange(ADDR, toBase64(outgoing.ed25519Public), served(signed));
    expect(change).toEqual({ kind: 'replaced', at: signed.rotatedAt });
  });

  it('reports a tombstoned key as stolen, and that outranks the handover', async () => {
    // Both are true of the same key — it was handed over AND declared stolen — and the reader
    // needs the heavier one. "They re-keyed" would be accurate and useless here.
    const outgoing = await generateIdentityKeyPair();
    const signed = await signRotation({ ...(await inputs(ADDR, outgoing, 1)), severity: 'compromised' });
    const change = await explainKeyChange(ADDR, toBase64(outgoing.ed25519Public), served(signed, {
      removal: toBase64(signed.compromise[0].removal),
    }));
    expect(change).toEqual({ kind: 'reported-stolen', at: signed.rotatedAt });
  });

  it('explains nothing about a key that was never in the lineage', async () => {
    const outgoing = await generateIdentityKeyPair();
    const stranger = await generateIdentityKeyPair();
    const signed = await signRotation(await inputs(ADDR, outgoing, 1));
    const change = await explainKeyChange(ADDR, toBase64(stranger.ed25519Public), served(signed));
    expect(change).toEqual({ kind: 'unexplained' });
  });

  it('explains nothing when the chain does not verify', async () => {
    // A forged lineage must read as no evidence at all. Reporting it as a replacement would hand
    // a hostile fleet exactly the reassurance the pin exists to withhold.
    const outgoing = await generateIdentityKeyPair();
    const signed = await signRotation(await inputs(ADDR, outgoing, 1));
    const rec = await decodeIdentityRecord(signed.record);
    rec.rotationChain[0].signature[0] ^= 0xff;
    const tampered = await encodeIdentityRecord({ ...rec, version: Number(rec.version), createdAt: Number(rec.createdAt), revision: Number(rec.revision), expiresAt: 0, verificationTier: 0, relayHints: [] });
    const change = await explainKeyChange(ADDR, toBase64(outgoing.ed25519Public), {
      address: ADDR, record: toBase64(tampered),
    });
    expect(change).toEqual({ kind: 'unexplained' });
  });

  it('ignores a tombstone signed by anyone but the key now holding the address', async () => {
    // The signer is the whole point: a stolen key is held by both parties and identifies neither,
    // so only the successor's signature makes the declaration mean anything.
    const outgoing = await generateIdentityKeyPair();
    const signed = await signRotation({ ...(await inputs(ADDR, outgoing, 1)), severity: 'compromised' });
    // Re-sign the same rotation from a DIFFERENT key, then keep that stranger's tombstone.
    const stranger = await signRotation({ ...(await inputs(ADDR, outgoing, 1)), severity: 'compromised' });
    const change = await explainKeyChange(ADDR, toBase64(outgoing.ed25519Public), served(signed, {
      removal: toBase64(stranger.compromise[0].removal),
    }));
    // Falls back to what the chain does say, rather than to the stranger's claim.
    expect(change.kind).toBe('replaced');
  });

  it('will not call it a replacement when some OTHER key authorized the handover', async () => {
    // The attack this distinction exists for. An impostor publishes a record for Alice's address
    // carrying a one-entry chain that NAMES her key as retired and their own as the authorizer.
    // Every signature on it is genuine — theirs — and the chain walk has nothing to object to,
    // because an entry's consent is checked against the key the entry itself names, and that key
    // is legitimately allowed to differ from the retired one. That is the recovery arm.
    //
    // So a forged lineage and a real recovery are the same shape from here, and the only honest
    // answer is the weaker one. Go can tell them apart because it holds the record being
    // displaced; this client does not.
    const victim = await generateIdentityKeyPair();     // the key the reader pinned
    const impostor = await generateIdentityKeyPair();   // the key taking the address
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const devicePublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));

    const entry = {
      version: 1,
      address: ADDR,
      retiredEd25519PublicKey: victim.ed25519Public,
      retiredX25519PublicKey: victim.x25519Public,
      nextEd25519PublicKey: impostor.ed25519Public,
      nextX25519PublicKey: impostor.x25519Public,
      rotatedAt: 1_800_000_000,
      nextRevision: 2,
      // The whole forgery, in one field: the impostor names THEMSELVES as the authority for
      // retiring a key they never held.
      authorizingEd25519PublicKey: impostor.ed25519Public,
      // Decoded, because the field is a MESSAGE: handing protobufjs raw bytes for it encodes an
      // empty credential, which names no device and fails the attestation check.
      deviceCredential: await decodeCredential(credentialFor(devicePublic)),
    } as Record<string, unknown>;
    const seed = impostor.ed25519Private.slice(0, 32);
    entry.deviceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey,
      bufferSource(rotationDeviceSigningBytes(await encodeRotationDeviceBytes(entry as never)))));
    entry.signature = await sign(seed, rotationConsentSigningBytes(await encodeRotationConsentBytes(entry as never)));
    entry.nextSignature = await sign(seed, rotationAcceptSigningBytes(await encodeRotationAcceptBytes(entry as never)));

    const base = {
      version: 1, address: ADDR,
      ed25519PublicKey: impostor.ed25519Public, x25519PublicKey: impostor.x25519Public,
      createdAt: 1_700_000_000, expiresAt: 0, relayHints: [], verificationTier: 0, revision: 2,
      rotationChain: [entry] as never,
    };
    const record = await encodeIdentityRecord({
      ...base,
      selfSignature: await signSelfSignature(seed, await encodeIdentitySignableBytes(base)),
    });

    const change = await explainKeyChange(ADDR, toBase64(victim.ed25519Public), { address: ADDR, record: toBase64(record) });
    // Dated and acknowledged, because something signed DOES describe the change — but never the
    // sentence that says the pinned key handed the address over, because it did not.
    expect(change).toEqual({ kind: 'recovered', at: 1_800_000_000 });
  });

  it('explains nothing from a record the owner did not sign', async () => {
    // The chain walk proves the entries agree with each other and with the keys the record
    // publishes. It says nothing about whether the owner published them — so a record altered
    // after signing would otherwise be read out of as if it were theirs.
    const outgoing = await generateIdentityKeyPair();
    const signed = await signRotation(await inputs(ADDR, outgoing, 1));
    const rec = await decodeIdentityRecord(signed.record);
    const tampered = await encodeIdentityRecord({
      ...rec, version: Number(rec.version), createdAt: Number(rec.createdAt), revision: Number(rec.revision),
      expiresAt: 0, relayHints: [],
      verificationTier: 2, // outside the chain, inside the self-signature
    });

    const change = await explainKeyChange(ADDR, toBase64(outgoing.ed25519Public), { address: ADDR, record: toBase64(tampered) });
    expect(change).toEqual({ kind: 'unexplained' });
  });

  it('consults the history when the key fell outside the record’s capped chain', async () => {
    // The case the history record exists for: an older key is no longer on the record at all.
    //
    // The clock is driven, because a chain entry has to be strictly LATER than the one before it
    // and two rotations in the same test land in the same second otherwise — which is a rule
    // worth tripping over here rather than in production.
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const first = await generateIdentityKeyPair();
    const one = await signRotation(await inputs(ADDR, first, 1));
    vi.setSystemTime(new Date('2026-06-01T00:00:00Z'));
    const priorHistory = (await decodeAddressHistory(one.history)).chain;
    const two = await signRotation({
      ...(await inputs(ADDR, one.next, 2, priorHistory)),
      currentRecord: {
        version: 1,
        revision: 2,
        createdAt: 1_700_000_000,
        expiresAt: 0,
        verificationTier: 0,
        rotationChain: (await decodeIdentityRecord(one.record)).rotationChain,
      },
    });

    // Trim the record's chain to its newest entry, which is what the cap does to a long-lived
    // account: the first key is gone from the record and survives only in the history.
    //
    // RE-SIGNED after trimming, because that is what really happens: the ceremony caps the chain
    // and then self-signs, so a genuinely capped record's signature covers the capped chain. A
    // record trimmed after signing is not a capped record, it is an altered one — and is refused
    // as such.
    const rec = await decodeIdentityRecord(two.record);
    const base = {
      ...rec, version: Number(rec.version), createdAt: Number(rec.createdAt),
      revision: Number(rec.revision), expiresAt: 0, verificationTier: 0, relayHints: [],
      rotationChain: [rec.rotationChain[rec.rotationChain.length - 1]],
      selfSignature: undefined,
    };
    const capped = await encodeIdentityRecord({
      ...base,
      selfSignature: await signSelfSignature(two.next.ed25519Private.slice(0, 32), await encodeIdentitySignableBytes(base)),
    });

    const answer = await explainKeyChange(ADDR, toBase64(first.ed25519Public), {
      address: ADDR, record: toBase64(capped), history: toBase64(two.history),
    });
    vi.useRealTimers();
    expect(answer).toEqual({ kind: 'replaced', at: one.rotatedAt });
  });
});
