import { describe, it, expect } from 'vitest';
import { signRotation, type RotationInputs } from './rotation';
import { decodeIdentityRecord, decodeAddressHistory } from './protobuf';
import { verifyRecordChain, verifyHistory, verifyChainLinks } from './verifyRotation';
import { generateIdentityKeyPair } from './keys';
import { bufferSource } from './bytes';

// The client verifies the lineage ITSELF. A pin exists to catch a fleet that serves one thing to
// one observer and another to another, so a lineage that same fleet merely asserted would be no
// counterweight at all. These tests are the check on that check: the browser's verifier has to
// accept exactly what Go's does.
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

async function inputs(address: string, overrides: Partial<RotationInputs> = {}): Promise<RotationInputs> {
  const current = await generateIdentityKeyPair();
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
    currentRecord: { version: 1, revision: 1, createdAt: 1_700_000_000, expiresAt: 0, verificationTier: 0, rotationChain: [] },
    deviceCredential: credentialFor(devicePublic),
    priorHistory: [],
    ...overrides,
  };
}

describe('verifying a rotation chain in the browser', () => {
  it('accepts a chain this client just produced', async () => {
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    expect(await verifyRecordChain(await decodeIdentityRecord(signed.record))).toBe('');
  });

  it('accepts the history beside it', async () => {
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const h = await decodeAddressHistory(signed.history);
    expect(await verifyHistory(h, 'alice@dmcn.email')).toBe('');
  });

  it('refuses a chain whose entry was signed for another address', async () => {
    // The binding that stops a genuine transition being lifted into someone else's history.
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const rec = await decodeIdentityRecord(signed.record);
    expect(await verifyChainLinks(rec.rotationChain, 'mallory@dmcn.email')).toContain('is for alice@dmcn.email');
  });

  it('refuses a chain that lands on a different key than the record publishes', async () => {
    // Without this a valid chain ending in some key could be carried by any record at all.
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const rec = await decodeIdentityRecord(signed.record);
    rec.ed25519PublicKey = new Uint8Array(32).fill(9);
    expect(await verifyRecordChain(rec)).toContain('different key');
  });

  it('refuses an entry whose consent signature was tampered with', async () => {
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const rec = await decodeIdentityRecord(signed.record);
    rec.rotationChain[0].signature[0] ^= 0xff;
    expect(await verifyRecordChain(rec)).toContain('did not consent');
  });

  it('refuses an entry whose acceptance signature was tampered with', async () => {
    // Consent alone would let a lineage be pointed at a key that never agreed to take it.
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const rec = await decodeIdentityRecord(signed.record);
    rec.rotationChain[0].nextSignature[0] ^= 0xff;
    expect(await verifyRecordChain(rec)).toContain('did not accept');
  });

  it('refuses a history that starts part-way through', async () => {
    // This record is where a reader goes when the capped on-record chain already fell short, so
    // one that begins mid-lineage defeats its own purpose.
    const signed = await signRotation(await inputs('alice@dmcn.email'));
    const h = await decodeAddressHistory(signed.history);
    h.chain[0].prevSignatureHash = new Uint8Array(32).fill(3);
    expect(await verifyHistory(h, 'alice@dmcn.email')).toContain('first rotation');
  });
});
