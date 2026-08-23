import { importX25519PublicKey } from './keys';

const CEK_WRAP_INFO = new TextEncoder().encode('dmcn-cek-wrap-v1');
const SIZE_CLASSES = [1024, 4096, 16384, 65536, 262144, 1048576];

export interface RecipientInfo {
  deviceId: Uint8Array;  // 16 bytes
  x25519Pub: Uint8Array; // 32 bytes
}

export interface RecipientRecord {
  deviceId: Uint8Array;
  recipientXPub: Uint8Array;
  ephemeralXPub: Uint8Array;
  wrappedCek: Uint8Array;
  cekNonce: Uint8Array;  // 12 bytes
  cekTag: Uint8Array;    // 16 bytes
}

export function selectSizeClass(payloadSize: number): number {
  // padPayload prepends a 4-byte length prefix; the bucket must fit payloadSize+4
  // so a payload at a class boundary is not truncated (parity with Go).
  const needed = payloadSize + 4;
  for (const sc of SIZE_CLASSES) {
    if (needed <= sc) return sc;
  }
  const mb = 1048576;
  return Math.ceil(needed / mb) * mb;
}

export function padPayload(payload: Uint8Array, targetSize: number): Uint8Array {
  const padded = new Uint8Array(targetSize);
  // 4-byte big-endian length prefix
  const len = payload.length;
  padded[0] = (len >>> 24) & 0xff;
  padded[1] = (len >>> 16) & 0xff;
  padded[2] = (len >>> 8) & 0xff;
  padded[3] = len & 0xff;
  padded.set(payload, 4);
  return padded;
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array; tag: Uint8Array }> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, plaintext)
  );
  return {
    nonce,
    ciphertext: encrypted.slice(0, encrypted.length - 16),
    tag: encrypted.slice(encrypted.length - 16),
  };
}

export async function wrapCEK(cek: Uint8Array, recipient: RecipientInfo): Promise<RecipientRecord> {
  // Generate ephemeral X25519 key pair
  const ephKey = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephKey.publicKey));

  // Import recipient public key
  const recipientPub = await importX25519PublicKey(recipient.x25519Pub);

  // Compute shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: recipientPub },
    ephKey.privateKey,
    256
  );
  const shared = new Uint8Array(sharedBits);

  // Derive key-wrapping key via HKDF
  const sharedKey = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const kwk = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: CEK_WRAP_INFO },
    sharedKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );

  // Wrap CEK
  const kwkRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kwk));
  const { nonce, ciphertext, tag } = await aesGcmEncrypt(kwkRaw, cek);

  return {
    deviceId: recipient.deviceId,
    recipientXPub: recipient.x25519Pub,
    ephemeralXPub: ephPubRaw,
    wrappedCek: ciphertext,
    cekNonce: nonce,
    cekTag: tag,
  };
}
