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
import { fromBase64, keyPairFromPayloadJSON, toBase64 } from './keys';
import {
  type EncryptedBundle, type KdfParams, ARGON2_PARAMS, decryptKeys, decryptKeysWithKey,
  deriveDeviceKey, encryptKeysWithKey, importBundleKey,
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
  // Password path: ONE salt for the whole store, so unlocking runs Argon2id once however many
  // accounts are attached. It used to wrap each entry with its own salt, which meant N runs of a
  // deliberately memory-hard KDF back to back — slow everywhere and a genuine hazard on a phone,
  // where a WKWebView under memory pressure can fail one of them and (before this) drop that
  // account in silence. Entries written the old way carry their own kdf tag and still open; they
  // convert as they are re-attached.
  salt?: string;         // base64
  kdfParams?: KdfParams;
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

// The device secret, as the two operations anything here needs from it. Derived ONCE per unlock.
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
  const salt = ks.salt ? fromBase64(ks.salt) : null;
  const shared = salt ? await deriveDeviceKey(password, salt, ks.kdfParams ?? ARGON2_PARAMS) : null;
  return {
    wrap: async bytes => {
      if (!shared) throw new Error('this device’s secret has no salt to wrap with');
      return encryptKeysWithKey(bytes, shared);
    },
    // An entry carrying its own kdf was written before the shared salt existed, and opens the way
    // it was written. Self-describing, so the two shapes coexist without a version check.
    unwrap: bundle => (bundle.kdf === 'argon2id'
      ? decryptKeys(bundle, password)
      : shared ? decryptKeysWithKey(bundle, shared) : Promise.reject(new Error('no device key'))),
  };
}

/**
 * Open every attached account.
 *
 * One prompt, N key pairs — but by way of each account's OWN keystore, which is where the identity
 * actually lives. The device secret yields a bundle key; that key opens the bundle; the bundle
 * holds the key pair. The caller imports each into non-extractable handles and drops the rest.
 */
export interface DeviceUnlockResult {
  opened: Record<string, IdentityKeyPair>;
  // Every account this unlock could NOT open, and why. Reported rather than skipped in silence:
  // an account quietly missing from the result is indistinguishable from one that was never
  // attached, which is how "it only unlocks one mailbox" could happen with nothing to go on.
  skipped: Array<{ address: string; reason: string }>;
}

export async function unlockDevice(opts?: { password?: string }): Promise<DeviceUnlockResult> {
  const ks = await loadDeviceKeystore();
  if (!ks) throw new Error('this device has no shared unlock set up');
  const key = await keyFor(ks, opts?.password);
  const opened: Record<string, IdentityKeyPair> = {};
  const skipped: DeviceUnlockResult['skipped'] = [];
  for (const [address, entry] of Object.entries(ks.entries)) {
    const account = await loadLocalKeystore(address);
    if (!account?.bundle) {
      skipped.push({ address, reason: 'it is no longer set up on this device' });
      continue;
    }
    if (account.bundle.nonce !== entry.opens) {
      skipped.push({ address, reason: 'its keystore was replaced after it was attached' });
      continue;
    }
    let bundleKey: Uint8Array;
    try {
      bundleKey = await key.unwrap(entry.key);
    } catch (e) {
      skipped.push({ address, reason: `this device's secret did not open its entry (${short(e)})` });
      continue;
    }
    try {
      opened[address] = keyPairFromPayloadJSON(
        await decryptKeysWithKey(account.bundle, await importBundleKey(bundleKey)));
    } catch (e) {
      skipped.push({ address, reason: `its own keystore did not open (${short(e)})` });
    }
  }
  if (Object.keys(opened).length === 0) {
    throw new Error(skipped.length
      ? `that opened nothing on this device — ${skipped.map(s => `${s.address}: ${s.reason}`).join('; ')}`
      : 'that did not unlock anything on this device');
  }
  return { opened, skipped };
}

function short(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.length > 80 ? `${m.slice(0, 80)}…` : m;
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
    // A store written before the shared salt has none; mint one now so this entry and everything
    // after it takes the one-derivation path. Entries already there keep their own and still open.
    if (existing.authMethod === 'password' && !existing.salt) {
      if (!params.password) throw new DevicePasswordRequiredError();
      existing.salt = toBase64(crypto.getRandomValues(new Uint8Array(32)));
      existing.kdfParams = ARGON2_PARAMS;
    }
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
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const shared = await deriveDeviceKey(password, salt, ARGON2_PARAMS);
  await idbPut(DEVICE_STORE, KEY, {
    v: 1,
    authMethod: 'password',
    salt: toBase64(salt),
    kdfParams: ARGON2_PARAMS,
    entries: { [address]: { key: await encryptKeysWithKey(bundleKey, shared), opens } },
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
