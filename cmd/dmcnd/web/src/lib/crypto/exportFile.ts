// User-held encrypted backup file — the total-device-loss safety net. The user
// downloads it and stores it themselves; the server never holds it.
//
// New exports are protected one way only:
//   - passcode: a code generated at export time (crypto/passcode.ts), which the person
//               saves to a password manager or writes down. It shares nothing with how
//               the account unlocks day to day, so losing a passkey or forgetting a
//               device password does not take the exported key with it.
//
// Files made before that can still be read, so nobody's existing backup stops working:
//   - password: Argon2id-wrapped under a passphrase the person chose.
//   - passkey:  WebAuthn-PRF-wrapped. Opens only where that passkey is available, and is
//               lost with it. That coupling is why new backups no longer offer it.

import { encryptKeysWithKey, decryptKeys, decryptKeysWithKey, type EncryptedBundle } from './keystore';
import { unlockPasskeyPRF } from './passkey';
import { passcodeKey } from './passcode';
import { type IdentityKeyPair, keyPairFromPayloadJSON, keyPairToPayloadJSON, toBase64, fromBase64 } from './keys';

export const EXPORT_FORMAT = 'dmcn-keystore-export';
export type ExportAuth = 'password' | 'passkey' | 'passcode';

export interface KeystoreExport {
  format: typeof EXPORT_FORMAT;
  version: 1;
  address: string;
  ed25519Public: string;   // base64, for at-a-glance identification
  authMethod: ExportAuth;
  credentialId?: string;   // base64 (passkey path)
  prfSalt?: string;        // base64 (passkey path)
  bundle: EncryptedBundle; // the wrapped key payload
}

function payloadOf(kp: IdentityKeyPair): Uint8Array {
  return new TextEncoder().encode(keyPairToPayloadJSON(kp));
}

// buildPasscodeExport wraps the keys under a key derived from passcode (any form
// normalizePasscode accepts).
export async function buildPasscodeExport(address: string, kp: IdentityKeyPair, passcode: string): Promise<KeystoreExport> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const bundle = await encryptKeysWithKey(payloadOf(kp), await passcodeKey(passcode, salt, ['encrypt']));
  return {
    format: EXPORT_FORMAT,
    version: 1,
    address,
    ed25519Public: toBase64(kp.ed25519Public),
    authMethod: 'passcode',
    bundle: { ...bundle, salt: toBase64(salt), kdf: 'hkdf-sha256' },
  };
}

export interface ReadExportResult {
  kp: IdentityKeyPair;
  // Present only for a passkey-protected backup: the PRF key + its metadata from the
  // unlock assertion. A successful passkey read proves that credential exists on THIS
  // device, so the importer can re-wrap the local keystore under the SAME passkey —
  // avoiding a second enrollment (which would mint a colliding credential) and a
  // second WebAuthn prompt.
  passkey?: { credentialId: string; prfSalt: string; aesKey: CryptoKey };
}

// readExport decrypts a backup. Passkey exports trigger a WebAuthn assertion against the
// stored credential and return the derived key so the caller can reuse it without
// prompting again. Passcode and passphrase exports both take the secret in
// opts.password: the import form has one secret field, and the file says which it is.
export async function readExport(exp: KeystoreExport, opts?: { password?: string }): Promise<ReadExportResult> {
  if (exp?.format !== EXPORT_FORMAT) throw new Error('not a DMCN keystore export file');
  if (exp.authMethod === 'passkey') {
    if (!exp.credentialId || !exp.prfSalt) throw new Error('backup is missing passkey metadata');
    const aesKey = await unlockPasskeyPRF(exp.credentialId, exp.prfSalt);
    const bytes = await decryptKeysWithKey(exp.bundle, aesKey);
    return { kp: keyPairFromPayloadJSON(bytes), passkey: { credentialId: exp.credentialId, prfSalt: exp.prfSalt, aesKey } };
  }
  if (exp.authMethod === 'passcode') {
    if (!opts?.password) throw new Error('passcode required');
    const key = await passcodeKey(opts.password, fromBase64(exp.bundle.salt), ['decrypt']);
    let bytes: Uint8Array;
    try {
      bytes = await decryptKeysWithKey(exp.bundle, key);
    } catch {
      // AES-GCM says only "no". A well-formed passcode that fails is a typo or the wrong file.
      throw new Error('that passcode does not open this file. Check it for typos, and that the file is the one it was made with');
    }
    return { kp: keyPairFromPayloadJSON(bytes) };
  }
  if (!opts?.password) throw new Error('passphrase required');
  const bytes = await decryptKeys(exp.bundle, opts.password);
  return { kp: keyPairFromPayloadJSON(bytes) };
}

// exportFileName is the name the exported file is saved under, so the page can say where it went.
export function exportFileName(address: string): string {
  return `dmcn-keystore-${address.replace(/[^a-z0-9._@-]/gi, '_')}.json`;
}

// triggerDownload hands the export to the browser to save as a local file.
export function triggerDownload(exp: KeystoreExport): void {
  const blob = new Blob([JSON.stringify(exp, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = exportFileName(exp.address);
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
