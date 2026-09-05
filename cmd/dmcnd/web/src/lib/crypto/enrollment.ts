// Getting a new identity onto this device.
//
// WHERE an address comes from is the deployment's business — a hosted funnel service, a
// self-hosted daemon that is its own operator, or an admin answering a petition. What
// happens in the browser is the same either way, and is the part that must not vary: the
// keypair is generated here, the identity record is self-signed here, and the only at-rest
// copy of the private keys is an encrypted blob written to this device's IndexedDB. Nothing
// secret goes to any server, whichever server it is.
//
// So this module owns the ceremony and each deployment's register screen owns the API call
// it wraps around it.

import { generateIdentityKeyPair, importEd25519PrivateKey, toBase64, type IdentityKeyPair } from './keys';
import { encryptKeys, encryptKeysWithKey, type EncryptedBundle } from './keystore';
import { makeLocalKeystore, saveLocalKeystore } from './localKeystore';
import { createPasskeyPRF } from './passkey';
import { encodeIdentitySignableBytes, encodeIdentityRecord } from './protobuf';
import { signSelfSignature } from './identity';
import { getRelayHints, loginWithKeys } from '../api/client';

/** How the on-device keystore is locked. */
export type UnlockChoice = { method: 'passkey' } | { method: 'passphrase'; passphrase: string };

export interface EnrolledIdentity {
  keys: IdentityKeyPair;
  /** The Ed25519 seed, kept out of the keystore round trip for the sign-in that follows. */
  seed: Uint8Array;
  /** The self-signed record to hand to whoever publishes it, and its signature. */
  identityRecordBytes: Uint8Array;
  selfSignature: Uint8Array;
  /** The encrypted keystore this device will re-unlock with. */
  bundle: EncryptedBundle;
  authMethod: 'password' | 'passkey';
  credentialId?: string;
  prfSalt?: string;
}

// buildSelfSignedRecord assembles the identity record for an address and signs it with the
// owner's own key. Exported separately because an address obtained out of band (a petition
// answered by an admin) reaches this point with a keypair it already holds.
export async function buildSelfSignedRecord(
  address: string,
  keys: IdentityKeyPair,
): Promise<{ identityRecordBytes: Uint8Array; selfSignature: Uint8Array; seed: Uint8Array }> {
  // The record's relay hints are advisory: the operator authoritatively sets them in the
  // routing credential it attaches. Fetch what the node reports so the self-signed core
  // already carries them.
  const { relay_hints } = await getRelayHints(address);
  const recordBase = {
    version: 1, address,
    ed25519PublicKey: keys.ed25519Public, x25519PublicKey: keys.x25519Public,
    createdAt: keys.createdAt, expiresAt: 0, relayHints: relay_hints,
    verificationTier: 0,
    // Match Go's NewIdentityRecord, which starts at 1. Covered by the self-signature, and
    // canonical() strips defaults — so 1 is emitted where 0 was stripped. Old records keep
    // verifying: Verify() recomputes the signable bytes from the record's own fields.
    revision: 1,
  };
  const signableBytes = await encodeIdentitySignableBytes(recordBase);
  const seed = keys.ed25519Private.slice(0, 32);
  const selfSignature = await signSelfSignature(seed, signableBytes);
  const identityRecordBytes = await encodeIdentityRecord({ ...recordBase, selfSignature });
  return { identityRecordBytes, selfSignature, seed };
}

// enrollIdentity mints a keypair for `address`, wraps it under the chosen unlock method, and
// self-signs its identity record — everything a register screen needs before it asks its own
// backend to publish the result.
//
// The passkey ceremony runs FIRST, before the (fast) key generation, so the WebAuthn prompt
// fires inside the submitting form's user activation. Reordering this breaks passkey
// enrollment on Safari, which drops the activation across an intervening await.
export async function enrollIdentity(address: string, unlock: UnlockChoice): Promise<EnrolledIdentity> {
  const enr = unlock.method === 'passkey' ? await createPasskeyPRF(address) : null;

  const keys = await generateIdentityKeyPair();
  const keyData = new TextEncoder().encode(JSON.stringify({
    ed25519_public: toBase64(keys.ed25519Public),
    ed25519_private: toBase64(keys.ed25519Private),
    x25519_public: toBase64(keys.x25519Public),
    x25519_private: toBase64(keys.x25519Private),
    device_id: toBase64(keys.deviceId),
    created_at: keys.createdAt,
  }));

  // The encrypted keystore lives only on this device (IndexedDB) — never sent to any
  // server. Passkey-PRF or Argon2id-passphrase wraps it.
  let bundle: EncryptedBundle;
  let authMethod: 'password' | 'passkey';
  let credentialId: string | undefined;
  let prfSalt: string | undefined;
  if (enr) {
    bundle = await encryptKeysWithKey(keyData, enr.aesKey);
    authMethod = 'passkey'; credentialId = enr.credentialId; prfSalt = enr.prfSalt;
  } else {
    bundle = await encryptKeys(keyData, unlock.method === 'passphrase' ? unlock.passphrase : '');
    authMethod = 'password';
  }

  const { identityRecordBytes, selfSignature, seed } = await buildSelfSignedRecord(address, keys);
  return { keys, seed, identityRecordBytes, selfSignature, bundle, authMethod, credentialId, prfSalt };
}

// persistIdentity writes the encrypted keystore so this device can re-unlock later.
//
// Separate from signing in because they are not always adjacent: on a domain that holds a
// registration for approval there is an address but not yet an account, and the keystore
// still has to be on the device — otherwise someone registers, waits for an admin, and comes
// back to a browser that has never heard of them.
//
// Called only after the address is actually accepted — a keystore for an address that was
// refused would be an account the user could unlock and never use.
export async function persistIdentity(address: string, e: EnrolledIdentity): Promise<void> {
  await saveLocalKeystore(makeLocalKeystore({
    address, kp: e.keys, bundle: e.bundle,
    authMethod: e.authMethod, credentialId: e.credentialId, prfSalt: e.prfSalt,
  }));
}

// signInWithEnrolled signs in with the fresh keys and returns the session token. Registration
// itself mints no session: the address has to prove itself to the mail client like any other.
export async function signInWithEnrolled(address: string, e: EnrolledIdentity): Promise<string> {
  const signKey = await importEd25519PrivateKey(e.seed);
  return loginWithKeys(address, signKey);
}

// persistAndSignIn is the two together, for the common case where nothing happens between.
export async function persistAndSignIn(address: string, e: EnrolledIdentity): Promise<string> {
  await persistIdentity(address, e);
  return signInWithEnrolled(address, e);
}
