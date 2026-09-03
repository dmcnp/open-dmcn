import { argon2id } from '@noble/hashes/argon2';
import { toBase64, fromBase64 } from './keys';
import { bufferSource } from './bytes';

// The password path wraps the identity keys under a key derived from the user's
// passphrase. The derivation is Argon2id (memory-hard) rather than a fast KDF: the
// encrypted blob now lives only client-side (IndexedDB) and may be exported to a
// file, so a stolen blob must resist offline cracking. The bundle is self-describing
// (kdf + params) so decrypt needs no out-of-band knowledge. The passkey path
// (encryptKeysWithKey/decryptKeysWithKey) derives its AES key from a WebAuthn PRF
// secret that never leaves the authenticator and needs no KDF here.

export interface EncryptedBundle {
  salt: string;       // base64 (Argon2id salt for the password path; '' for passkey)
  nonce: string;      // base64 (12 bytes IV)
  ciphertext: string; // base64
  tag: string;        // base64 (16 bytes)
  kdf?: 'argon2id';   // present for the password path; absent for the passkey path
  kdfParams?: KdfParams;
}

export interface KdfParams {
  m: number; // memory cost in KiB
  t: number; // iterations (time cost)
  p: number; // parallelism
}

// Interactive-unlock parameters. ~19 MiB keeps pure-JS Argon2id to a sub-second
// unlock on current hardware while staying above the OWASP floor (m=19456, t=2, p=1).
const ARGON2_PARAMS: KdfParams = { m: 19456, t: 2, p: 1 };

async function derivePassphraseKey(
  passphrase: string,
  salt: Uint8Array,
  params: KdfParams,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const raw = argon2id(new TextEncoder().encode(passphrase), salt, {
    t: params.t,
    m: params.m,
    p: params.p,
    dkLen: 32,
  });
  return crypto.subtle.importKey('raw', bufferSource(raw), 'AES-GCM', false, usage);
}

// encryptKeysWithKey/decryptKeysWithKey use a pre-derived AES-GCM key instead of
// a passphrase — used by the passkey (WebAuthn PRF) path, where the key comes
// from the authenticator. The bundle's salt is empty and no kdf tag is set.
export async function encryptKeysWithKey(keyBytes: Uint8Array, aesKey: CryptoKey): Promise<EncryptedBundle> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, bufferSource(keyBytes))
  );
  return {
    salt: '',
    nonce: toBase64(nonce),
    ciphertext: toBase64(encrypted.slice(0, encrypted.length - 16)),
    tag: toBase64(encrypted.slice(encrypted.length - 16)),
  };
}

export async function decryptKeysWithKey(bundle: EncryptedBundle, aesKey: CryptoKey): Promise<Uint8Array> {
  const ciphertext = fromBase64(bundle.ciphertext);
  const tag = fromBase64(bundle.tag);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bufferSource(fromBase64(bundle.nonce)), tagLength: 128 },
    aesKey,
    combined
  );
  return new Uint8Array(decrypted);
}

export async function encryptKeys(keyBytes: Uint8Array, passphrase: string): Promise<EncryptedBundle> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const aesKey = await derivePassphraseKey(passphrase, salt, ARGON2_PARAMS, ['encrypt']);

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, bufferSource(keyBytes))
  );

  // Web Crypto appends the tag to the ciphertext — split them.
  return {
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(encrypted.slice(0, encrypted.length - 16)),
    tag: toBase64(encrypted.slice(encrypted.length - 16)),
    kdf: 'argon2id',
    kdfParams: ARGON2_PARAMS,
  };
}

export async function decryptKeys(bundle: EncryptedBundle, passphrase: string): Promise<Uint8Array> {
  const params = bundle.kdfParams ?? ARGON2_PARAMS;
  const aesKey = await derivePassphraseKey(passphrase, fromBase64(bundle.salt), params, ['decrypt']);

  const ciphertext = fromBase64(bundle.ciphertext);
  const tag = fromBase64(bundle.tag);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bufferSource(fromBase64(bundle.nonce)), tagLength: 128 },
    aesKey,
    combined
  );
  return new Uint8Array(decrypted);
}
