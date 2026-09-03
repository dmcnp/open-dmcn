import { importEd25519PrivateKey, importEd25519PublicKey } from './keys';
import { bufferSource } from './bytes';

// signWithKey signs with a non-extractable Ed25519 CryptoKey handle (the working
// key). Resident, day-to-day signing goes through this so the private bytes never
// re-enter JS reach.
export async function signWithKey(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('Ed25519', key, bufferSource(data));
  return new Uint8Array(sig);
}

// sign imports a raw 32-byte seed and signs. Kept for transient flows that
// legitimately hold raw bytes for the duration of one operation (identity self-sign
// at registration, device pairing, domain countersign).
export async function sign(ed25519Seed: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const key = await importEd25519PrivateKey(ed25519Seed);
  return signWithKey(key, data);
}

export async function verify(ed25519Pub: Uint8Array, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const key = await importEd25519PublicKey(ed25519Pub);
  return crypto.subtle.verify('Ed25519', key, bufferSource(signature), bufferSource(data));
}
