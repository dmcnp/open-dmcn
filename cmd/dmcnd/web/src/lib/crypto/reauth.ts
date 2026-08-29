// Re-prompt unlock for the operations that genuinely need the raw key bytes the
// non-extractable working handles can't yield: approving a new device (sealing the
// key bundle to its ephemeral key), exporting an encrypted backup, and changing the
// password. Each decrypts the LOCAL keystore for one operation and the caller
// discards the bytes — they are never kept resident and never come from a server.

import { type IdentityKeyPair, keyPairFromPayloadJSON } from './keys';
import { decryptKeys, decryptKeysWithKey } from './keystore';
import { unlockPasskeyPRF } from './passkey';
import { loadLocalKeystore, type AuthMethod, type LocalKeystore } from './localKeystore';

// Thrown when the local keystore is password-gated and the caller did not supply a
// password — the caller should prompt and retry with { password }.
export class PasswordRequiredError extends Error {
  constructor() {
    super('password required to unlock the local keystore');
    this.name = 'PasswordRequiredError';
  }
}

export async function localAuthMethod(address: string): Promise<AuthMethod | null> {
  const ks = await loadLocalKeystore(address);
  return ks ? ks.authMethod : null;
}

export interface UnlockResult {
  kp: IdentityKeyPair;
  // For a passkey-gated keystore: the PRF key + its metadata from the unlock
  // assertion, so a caller can re-wrap (e.g. a passkey-protected backup export)
  // without prompting for the passkey a second time.
  passkey?: { credentialId: string; prfSalt: string; aesKey: CryptoKey };
}

// unlockBackupBytes decrypts the local keystore to a raw key pair. For the passkey
// path the WebAuthn user-verification prompt is the gesture gate; for the password
// path the caller must pass the entered password.
export async function unlockBackupBytes(address: string, opts?: { password?: string }): Promise<UnlockResult> {
  const ks = await loadLocalKeystore(address);
  if (!ks) throw new Error('no local keystore on this device');
  return unlockKeystore(ks, opts);
}

// unlockKeystore is the same unlock against an ALREADY-LOADED keystore record. The
// account picker/switcher holds the record and must call this rather than
// unlockBackupBytes: an IndexedDB round trip between the click and
// navigator.credentials.get() can cost the transient user activation the passkey
// prompt needs (Safari), turning a valid unlock into a silent failure.
export async function unlockKeystore(ks: LocalKeystore, opts?: { password?: string }): Promise<UnlockResult> {
  if (ks.authMethod === 'passkey') {
    if (!ks.credentialId || !ks.prfSalt) throw new Error('local keystore is missing passkey metadata');
    const aesKey = await unlockPasskeyPRF(ks.credentialId, ks.prfSalt);
    const keyBytes = await decryptKeysWithKey(ks.bundle, aesKey);
    return {
      kp: keyPairFromPayloadJSON(keyBytes),
      passkey: { credentialId: ks.credentialId, prfSalt: ks.prfSalt, aesKey },
    };
  }
  if (!opts?.password) throw new PasswordRequiredError();
  const keyBytes = await decryptKeys(ks.bundle, opts.password);
  return { kp: keyPairFromPayloadJSON(keyBytes) };
}
