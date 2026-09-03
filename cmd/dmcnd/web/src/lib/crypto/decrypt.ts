import { importX25519PublicKey } from './keys';
import { cekWrapInfo } from './sealVersion';
import { bufferSource } from './bytes';

interface RecipientRecord {
  recipientXPub: Uint8Array;
  ephemeralXPub: Uint8Array;
  wrappedCek: Uint8Array;
  cekNonce: Uint8Array;
  cekTag: Uint8Array;
  kdf?: number;
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const aesKey = await crypto.subtle.importKey('raw', bufferSource(key), 'AES-GCM', false, ['decrypt']);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  const gcm = { name: 'AES-GCM', iv: bufferSource(nonce), tagLength: 128, ...(aad ? { additionalData: bufferSource(aad) } : {}) };
  const decrypted = await crypto.subtle.decrypt(gcm, aesKey, combined);
  return new Uint8Array(decrypted);
}

// unpadPayload strips the 4-byte big-endian length prefix padPayload wrote.
//
// The `>>> 0` is not cosmetic. `<<` in JS yields a SIGNED 32-bit result, so a prefix with the
// high bit set produced a NEGATIVE length: the bounds check below passed, slice() clamped, and
// this returned an EMPTY array where Go returned the whole padded buffer — the two
// implementations silently disagreeing on malformed input. Both now throw.
//
// The prefix lives inside the AEAD, so by the time this runs the bytes are authenticated: a bad
// value means the caller opened something padPayload never produced.
export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) {
    throw new Error(`unpad: buffer is ${padded.length} bytes, shorter than its length prefix`);
  }
  const actualLen =
    ((padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3]) >>> 0;
  if (actualLen + 4 > padded.length) {
    throw new Error(`unpad: length prefix ${actualLen} exceeds the ${padded.length}-byte buffer`);
  }
  return padded.slice(4, 4 + actualLen);
}

// unwrapCEK recovers the CEK from a recipient record.
//
// x25519Pub is the READER'S OWN public key, not rec.recipientXPub. The generation-2 derivation
// binds the key-wrapping key to the recipient it was sealed for, and taking that from the record
// would bind it to a field the sealer chose rather than one the reader knows. Go's unwrapCEK
// takes the same parameter for the same reason — openSealed there tries records whose
// recipientXPub is not ours, and must not derive from them.
export async function unwrapCEK(
  rec: RecipientRecord,
  x25519Derive: CryptoKey,
  x25519Pub: Uint8Array
): Promise<Uint8Array> {
  // The record states its own derivation generation (kdf, absent meaning 1), so this dispatches
  // rather than guessing. No trial decryption.
  const info = cekWrapInfo(rec.kdf ?? 0, rec.ephemeralXPub, x25519Pub);

  // Compute shared secret with the recipient's non-extractable X25519 handle.
  // deriveBits works on a non-extractable key — the private bytes never leave it.
  const ephPub = await importX25519PublicKey(rec.ephemeralXPub);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: ephPub },
    x25519Derive,
    256
  );
  const sharedKey = await crypto.subtle.importKey('raw', new Uint8Array(sharedBits), 'HKDF', false, ['deriveKey']);
  const kwk = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: bufferSource(info) },
    sharedKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );
  const kwkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kwk));
  return aesGcmDecrypt(kwkRaw, rec.cekNonce, rec.wrappedCek, rec.cekTag);
}
