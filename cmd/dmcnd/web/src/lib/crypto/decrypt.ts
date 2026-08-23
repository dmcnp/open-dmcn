import { importX25519PublicKey } from './keys';

const CEK_WRAP_INFO = new TextEncoder().encode('dmcn-cek-wrap-v1');

interface RecipientRecord {
  recipientXPub: Uint8Array;
  ephemeralXPub: Uint8Array;
  wrappedCek: Uint8Array;
  cekNonce: Uint8Array;
  cekTag: Uint8Array;
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Promise<Uint8Array> {
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    combined
  );
  return new Uint8Array(decrypted);
}

export function unpadPayload(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) return padded;
  const actualLen = (padded[0] << 24) | (padded[1] << 16) | (padded[2] << 8) | padded[3];
  if (actualLen + 4 > padded.length) return padded;
  return padded.slice(4, 4 + actualLen);
}

export async function unwrapCEK(rec: RecipientRecord, x25519Derive: CryptoKey): Promise<Uint8Array> {
  // Compute shared secret with the recipient's non-extractable X25519 handle.
  // deriveBits works on a non-extractable key — the private bytes never leave it.
  const ephPub = await importX25519PublicKey(rec.ephemeralXPub);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: ephPub },
    x25519Derive,
    256
  );
  const shared = new Uint8Array(sharedBits);

  // Derive key-wrapping key
  const sharedKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const kwk = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: CEK_WRAP_INFO },
    sharedKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );

  const kwkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kwk));
  return aesGcmDecrypt(kwkRaw, rec.cekNonce, rec.wrappedCek, rec.cekTag);
}
