import { describe, it, expect } from 'vitest';
import { bufferSource } from './bytes';
import { deviceApprovalBytes, deviceRetirementBytes, deviceChallengeBytes } from './deviceKey';

// Known-answer vectors for the bytes an enrolled device signs to act on another device. The Go
// half is TestParityVectorDeviceActions in internal/core/identity/deviceparity_test.go, with the
// same constants.
//
// These signatures are what a relay checks before letting a device onto a mailbox or cutting one
// off, so an encoder that drifted would not fail loudly — it would refuse every approval, and the
// reason would be invisible from either side.
//
// Fixed inputs: subject device key = 32x0x21, nonce = 32x0x22, attested at 1700000000, and the
// address in MIXED CASE so the lowercasing is actually exercised.
const VEC = {
  approve: '646d636e2d6465766963652d617070726f76652d763100766563746f72407061726974792e6578616d706c6521212121212121212121212121212121212121212121212121212121212121212222222222222222222222222222222222222222222222222222222222222222000000006553f100',
  retire: '646d636e2d6465766963652d7265746972652d763100766563746f72407061726974792e6578616d706c6521212121212121212121212121212121212121212121212121212121212121212222222222222222222222222222222222222222222222222222222222222222',
  challenge: '646d636e2d6465766963652d6368616c6c656e67652d7631002222222222222222222222222222222222222222222222222222222222222222',
};

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

const SUBJECT = fill(32, 0x21);
const NONCE = fill(32, 0x22);
const ADDRESS = 'Vector@Parity.Example';

describe('device action signing bytes (Go identity.deviceActionBytes)', () => {
  it('approval: context, lowercased address, subject, nonce, then the attested time', async () => {
    expect(hex(deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1_700_000_000))).toBe(VEC.approve);
  });

  it('retirement: the same shape with no time at all', async () => {
    expect(hex(deviceRetirementBytes(ADDRESS, SUBJECT, NONCE))).toBe(VEC.retire);
  });

  it('challenge: the tag and the nonce, and nothing else to bind', async () => {
    // The relay already knows which mailbox it asked about, so there is nothing else to name.
    // What the tag buys is that this can never also be an approval, whatever nonce is served.
    expect(hex(deviceChallengeBytes(NONCE))).toBe(VEC.challenge);
  });

  it('an absent time contributes nothing rather than a zero', () => {
    // Eight bytes of difference nobody would think to look for, if one side encoded a zero where
    // the other encoded nothing.
    const withTime = deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1_700_000_000);
    const retire = deviceRetirementBytes(ADDRESS, SUBJECT, NONCE);
    // Same fields either side of the context, so the length gap is the time plus the one byte the
    // two context tags differ by.
    expect(withTime.length - retire.length).toBe(9);
  });

  it('the attested time is big-endian, so the halves cannot be transposed', () => {
    const b = deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1);
    expect(hex(b.slice(-8))).toBe('0000000000000001');
  });

  it('capitalisation does not change the signed bytes', () => {
    // Addresses compare case-insensitively everywhere else; a signature that depended on the
    // caller's capitalisation would fail for reasons nobody could diagnose.
    expect(hex(deviceApprovalBytes('vector@parity.example', SUBJECT, NONCE, 1_700_000_000)))
      .toBe(hex(deviceApprovalBytes('VECTOR@PARITY.EXAMPLE', SUBJECT, NONCE, 1_700_000_000)));
  });

  it('approval and retirement are never interchangeable', () => {
    // One lets a device in and the other cuts one off. Distinct contexts are what stop an
    // approval captured from a pairing being replayed to remove the device that gave it.
    expect(hex(deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1_700_000_000)))
      .not.toBe(hex(deviceRetirementBytes(ADDRESS, SUBJECT, NONCE)));
  });
});

// The property the device registry rests on: a device key genuinely cannot travel.
//
// Everything else in the scheme follows from it. A relay demands both an account key and a device
// key, and that only buys anything if the second is absent from whatever a thief can copy — the
// backup export, the encrypted keystore, the pairing payload. Asserting "we did not put it there"
// would be a statement about today's code; asserting the PLATFORM refuses to hand it over is a
// statement about every future version too.
describe('device key custody', () => {
  it('is generated non-extractable, so its private half cannot be read back at all', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    expect(pair.privateKey.extractable).toBe(false);
    // Not "we choose not to export it" — the platform refuses.
    await expect(crypto.subtle.exportKey('pkcs8', pair.privateKey)).rejects.toThrow();
  });

  it('still yields a public half to enrol with', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    expect(raw.length).toBe(32);
  });

  it('signs with the handle it cannot export', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const msg = deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1_700_000_000);
    const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey, bufferSource(msg)));
    expect(sig.length).toBe(64);
    expect(await crypto.subtle.verify('Ed25519', pair.publicKey, bufferSource(sig), bufferSource(msg))).toBe(true);
    // And it verifies only over the bytes it actually signed.
    const other = deviceApprovalBytes(ADDRESS, SUBJECT, NONCE, 1_700_000_001);
    expect(await crypto.subtle.verify('Ed25519', pair.publicKey, bufferSource(sig), bufferSource(other))).toBe(false);
  });
});

// The travelling payloads must not carry a device key. The type system already prevents it — a
// device key is not part of IdentityKeyPair — but these are the three shapes that leave the
// device, so the exclusion is worth a regression guard rather than an assumption.
describe('device keys stay out of what travels', () => {
  const kp = {
    ed25519Public: fill(32, 0x01),
    ed25519Private: fill(64, 0x02),
    x25519Public: fill(32, 0x03),
    x25519Private: fill(32, 0x04),
    deviceId: fill(16, 0x05),
    createdAt: 1_700_000_000,
  };

  it('the keystore / export / pairing payload carries only account key material', async () => {
    const { keyPairToPayloadJSON } = await import('./keys');
    const fields = Object.keys(JSON.parse(keyPairToPayloadJSON(kp)));
    expect(fields.sort()).toEqual([
      'created_at', 'device_id', 'ed25519_private', 'ed25519_public', 'x25519_private', 'x25519_public',
    ]);
    // `device_id` is a label on the KEYPAIR, cloned wholesale by pairing — it identifies the key,
    // never a device, and must not be mistaken for one. The device's own signing key has no
    // representation here at all, which is the point.
    expect(fields).not.toContain('device_private');
    expect(fields).not.toContain('device_key');
  });
});
