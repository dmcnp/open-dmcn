// One secret on this device, opening several accounts.
//
// Every account already has its own encrypted keystore with its own passkey or password, and that
// stays the one and only encrypted copy of its private key. This adds an optional second way IN to
// that same copy: for each attached account it stores the KEY that opens that account's bundle,
// itself encrypted under a single device secret. Unlocking once yields those keys, which open the
// bundles that were already there.
//
// Storing the key rather than another wrapping of the identity is the whole point. A second
// wrapping would mean two independently decryptable copies of the same private key living side by
// side — twice the ciphertext to steal offline, and two places to remember to erase. There is
// exactly one, in the account's own keystore, where it always was.
//
// What it costs is worth saying plainly, and the UI says it at the moment of attaching: one secret
// now opens every attached account on this device. The keys are no less protected at rest — the
// same AES-GCM, the same Argon2id or the same WebAuthn PRF — but there is one more door.
//
// Each account's key is wrapped SEPARATELY under the shared secret rather than all of them into
// one blob, so attaching or detaching one never needs the others in the clear, and a single
// unreadable entry costs one account rather than the whole unlock.

import type { IdentityKeyPair } from './keys';
import { keyPairFromPayloadJSON } from './keys';
import {
  type EncryptedBundle, decryptKeys, decryptKeysWithKey, encryptKeys, encryptKeysWithKey,
  importBundleKey,
} from './keystore';
import { createPasskeyPRF, unlockPasskeyPRF } from './passkey';
import { type AuthMethod, type LocalKeystore, loadLocalKeystore } from './localKeystore';
import { DEVICE_STORE, idbGet, idbPut, idbDelete } from './idb';

const KEY = 'secret';

export interface DeviceKeystore {
  v: 1;
  authMethod: AuthMethod;
  credentialId?: string; // base64 (passkey path)
  prfSalt?: string;      // base64 (passkey path)
  // Per attached account: that account's bundle key, encrypted under the device secret. NOT its
  // identity — the identity stays in its own keystore, wrapped once. Addresses are already in the
  // clear on this device (the account list shows them while locked), so naming them here reveals
  // nothing new, and it lets the UI say which accounts one unlock would open.
  //
  // `opens` is the nonce of the bundle that key was made for. Re-wrapping an account (its password
  // changed, or it was re-imported or re-paired) mints a new bundle with a new nonce, and the
  // stored key then opens nothing. Recording which bundle it belongs to turns that from a silent
  // failure — an account listed as attached that the shared unlock quietly skips — into a plain
  // "not attached any more", with no call site having to remember to say so.
  entries: Record<string, { key: EncryptedBundle; opens: string }>;
  createdAt: number;
}

export async function loadDeviceKeystore(): Promise<DeviceKeystore | null> {
  try {
    return (await idbGet<DeviceKeystore>(DEVICE_STORE, KEY)) ?? null;
  } catch {
    return null;
  }
}

/**
 * The accounts one unlock of this device would open. Readable without unlocking anything.
 *
 * An entry whose account has gone, or whose bundle has been re-wrapped since, is not counted: it
 * could not open anything, so reporting it would be a promise the unlock cannot keep.
 */
export async function attachedAddresses(): Promise<string[]> {
  const ks = await loadDeviceKeystore();
  if (!ks) return [];
  const live: string[] = [];
  for (const [address, entry] of Object.entries(ks.entries)) {
    if (await opensCurrentBundle(address, entry.opens)) live.push(address);
  }
  return live.sort();
}

export async function isAttached(address: string): Promise<boolean> {
  return (await attachedAddresses()).includes(address);
}

async function opensCurrentBundle(address: string, opens: string): Promise<boolean> {
  const account = await loadLocalKeystore(address);
  return !!account?.bundle && account.bundle.nonce === opens;
}

/**
 * Thrown when the device secret is a password and the caller supplied none. The caller prompts and
 * retries with { password } — the same contract as reauth.PasswordRequiredError, kept separate so a
 * caller can tell WHICH secret is being asked for.
 */
export class DevicePasswordRequiredError extends Error {
  constructor() {
    super('password required to unlock this device');
    this.name = 'DevicePasswordRequiredError';
  }
}

// The device secret, as the two operations anything here needs from it.
interface DeviceKey {
  wrap: (bytes: Uint8Array) => Promise<EncryptedBundle>;
  unwrap: (bundle: EncryptedBundle) => Promise<Uint8Array>;
}

async function keyFor(ks: DeviceKeystore, password?: string): Promise<DeviceKey> {
  if (ks.authMethod === 'passkey') {
    if (!ks.credentialId || !ks.prfSalt) throw new Error('this device’s secret is missing its passkey details');
    const aes = await unlockPasskeyPRF(ks.credentialId, ks.prfSalt);
    return {
      wrap: bytes => encryptKeysWithKey(bytes, aes),
      unwrap: bundle => decryptKeysWithKey(bundle, aes),
    };
  }
  if (!password) throw new DevicePasswordRequiredError();
  return {
    wrap: bytes => encryptKeys(bytes, password),
    unwrap: bundle => decryptKeys(bundle, password),
  };
}

/**
 * Open every attached account.
 *
 * One prompt, N key pairs — but by way of each account's OWN keystore, which is where the identity
 * actually lives. The device secret yields a bundle key; that key opens the bundle; the bundle
 * holds the key pair. The caller imports each into non-extractable handles and drops the rest.
 */
export async function unlockDevice(opts?: { password?: string }): Promise<Record<string, IdentityKeyPair>> {
  const ks = await loadDeviceKeystore();
  if (!ks) throw new Error('this device has no shared unlock set up');
  const key = await keyFor(ks, opts?.password);
  const out: Record<string, IdentityKeyPair> = {};
  for (const [address, entry] of Object.entries(ks.entries)) {
    try {
      const account = await loadLocalKeystore(address);
      // Gone, or re-wrapped since this key was stored — either way it opens nothing now.
      if (!account?.bundle || account.bundle.nonce !== entry.opens) continue;
      const bundleKey = await importBundleKey(await key.unwrap(entry.key));
      out[address] = keyPairFromPayloadJSON(await decryptKeysWithKey(account.bundle, bundleKey));
    } catch {
      // One entry that cannot be opened must not cost the others their unlock. Left on file, and
      // reported as unattached by attachedAddresses, so the UI never claims it works.
    }
  }
  if (Object.keys(out).length === 0) throw new Error('that did not unlock anything on this device');
  return out;
}

/**
 * Create the device secret with its first account, or add another to an existing one.
 *
 * `bundleKey` is the raw key that opens this account's own keystore bundle, obtained by unlocking
 * it the usual way (see reauth.bundleKeyFor). Note what is NOT passed: the identity. Attaching
 * never has the private key in hand, because it never needs it.
 */
export async function attachAccount(params: {
  address: string;
  bundleKey: Uint8Array;
  // Only for creating the secret: which method to use, and the password if it is one.
  create?: { authMethod: AuthMethod; password?: string };
  // Only for adding to an existing password-gated secret.
  password?: string;
}): Promise<void> {
  const { address, bundleKey } = params;
  const account = await loadLocalKeystore(address);
  if (!account?.bundle) throw new Error('this account has no keystore on this device');
  const opens = account.bundle.nonce;
  const existing = await loadDeviceKeystore();

  if (existing) {
    const key = await keyFor(existing, params.password);
    existing.entries = { ...existing.entries, [address]: { key: await key.wrap(bundleKey), opens } };
    await idbPut(DEVICE_STORE, KEY, existing);
    return;
  }

  const method = params.create?.authMethod ?? 'password';
  if (method === 'passkey') {
    const enrolled = await createPasskeyPRF(address);
    await idbPut(DEVICE_STORE, KEY, {
      v: 1,
      authMethod: 'passkey',
      credentialId: enrolled.credentialId,
      prfSalt: enrolled.prfSalt,
      entries: { [address]: { key: await encryptKeysWithKey(bundleKey, enrolled.aesKey), opens } },
      createdAt: Math.floor(Date.now() / 1000),
    } satisfies DeviceKeystore);
    return;
  }
  const password = params.create?.password;
  if (!password) throw new DevicePasswordRequiredError();
  await idbPut(DEVICE_STORE, KEY, {
    v: 1,
    authMethod: 'password',
    entries: { [address]: { key: await encryptKeys(bundleKey, password), opens } },
    createdAt: Math.floor(Date.now() / 1000),
  } satisfies DeviceKeystore);
}

/**
 * Take one account back out.
 *
 * Needs no secret: the entry is removed, not read. Nothing about the account changes — its own
 * keystore was never touched, and it goes on unlocking exactly as it did. Removing the last entry
 * removes the device secret entirely rather than leaving an empty shell that would still prompt.
 */
export async function detachAccount(address: string): Promise<void> {
  const ks = await loadDeviceKeystore();
  if (!ks || !(address in ks.entries)) return;
  const entries = { ...ks.entries };
  delete entries[address];
  if (Object.keys(entries).length === 0) {
    await forgetDeviceKeystore();
    return;
  }
  await idbPut(DEVICE_STORE, KEY, { ...ks, entries });
}

export async function forgetDeviceKeystore(): Promise<void> {
  try {
    await idbDelete(DEVICE_STORE, KEY);
  } catch { /* nothing to remove */ }
}

// Re-exported for the callers that only need the type.
export type { LocalKeystore };
