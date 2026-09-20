// The keys an account used to hold.
//
// A rotation re-keys the mailbox but does NOT re-seal what is in it: every message and every
// personal-storage blob is still sealed to the key it arrived under, and the relay cannot re-seal
// them because it cannot read them. So the old keys have to survive on the device that rotated —
// not to act with, only to open what they already opened.
//
// Two halves are kept, and only two:
//
//   - the X25519 derive handle, which opens mail and storage sealed to that generation;
//   - the HKDF alias root, because isolated aliases are DERIVED from the account's Ed25519 seed.
//     Losing it would strand every throwaway ever minted: nothing on the network enumerates them,
//     the new seed cannot re-derive them, and their mail would become permanently unreadable.
//
// The Ed25519 SIGNING key is deliberately not kept. Nothing should ever sign as a retired key
// again, and a copy that could would be the one piece a thief needs to forge a lineage.
import { DEVICE_STORE, idbGet, idbPut } from './idb';
import { importX25519PrivateKey } from './keys';
import type { IdentityKeyPair } from './keys';
import type { WorkingKeys } from './workingKeys';

/** One generation of an account's keys, after it stopped being current. */
export interface RetiredKeys {
  /** 0 is the account's first key, incrementing with each rotation. */
  generation: number;
  x25519Public: Uint8Array;
  /** Opens mail and storage sealed to this generation. Non-extractable. */
  x25519Derive: CryptoKey;
  /**
   * HKDF root for aliases minted under this generation. Non-extractable.
   *
   * Optional because a browser that could not revive the handle never had one. Where it is
   * missing, mail sent to a throwaway minted under this generation stays unreadable on this
   * device — the account's own mail is unaffected.
   */
  aliasRoot?: CryptoKey;
  /** Unix seconds — when this generation stopped being the account's current key. */
  retiredAt: number;
}

const retiredRef = (address: string) => `retired-keys:${address.toLowerCase()}`;

/**
 * Every generation this device still holds keys for, oldest first.
 *
 * An empty list is the ordinary answer for an account that has never rotated, and for a device
 * that joined after one — a paired device is handed only the CURRENT keys, so it can read mail
 * from this generation onward and nothing before it. That is a real limitation rather than a bug
 * to work around: the older ciphertext is readable only where the older key still lives.
 */
export async function retiredKeys(address: string): Promise<RetiredKeys[]> {
  try {
    const list = await idbGet<RetiredKeys[]>(DEVICE_STORE, retiredRef(address));
    return list ?? [];
  } catch {
    return [];
  }
}

/**
 * Keep the generation `keys` belonged to, before swapping in a new one.
 *
 * Called with the OUTGOING working keys while they are still loaded, which is the only moment both
 * generations exist on the device at once. Doing it after the keystore swap would mean asking the
 * user to unlock a key that is no longer theirs.
 */
export async function retainRetiredKeys(address: string, keys: WorkingKeys, retiredAt: number): Promise<void> {
  const existing = await retiredKeys(address);
  const entry: RetiredKeys = {
    generation: existing.length,
    x25519Public: keys.x25519Public,
    x25519Derive: keys.x25519Derive,
    aliasRoot: keys.aliasRoot,
    retiredAt,
  };
  await idbPut(DEVICE_STORE, retiredRef(address), [...existing, entry]);
}

/**
 * Rebuild a retired generation from raw key bytes.
 *
 * The rotation ceremony re-auths to get the outgoing seed anyway, so it can hand the raw pair
 * here rather than depending on the working handles still being loaded — which matters on the
 * resume path, where a ceremony picks up after the handles have gone.
 */
export async function retainRetiredFromKeyPair(address: string, kp: IdentityKeyPair, aliasRoot: CryptoKey | undefined, retiredAt: number): Promise<void> {
  const existing = await retiredKeys(address);
  if (existing.some(r => sameBytes(r.x25519Public, kp.x25519Public))) return; // already kept
  const entry: RetiredKeys = {
    generation: existing.length,
    x25519Public: kp.x25519Public,
    x25519Derive: await importX25519PrivateKey(kp.x25519Private),
    aliasRoot,
    retiredAt,
  };
  await idbPut(DEVICE_STORE, retiredRef(address), [...existing, entry]);
}

/**
 * Present a retired generation as working keys, for the one thing it may still do: decrypt.
 *
 * `ed25519Sign` is deliberately absent, so a caller cannot sign with a key the account has
 * retired even by accident — the type will not let them.
 */
export function asDecryptOnly(address: string, r: RetiredKeys): Pick<WorkingKeys, 'x25519Public' | 'x25519Derive' | 'aliasRoot' | 'address'> {
  return {
    address,
    x25519Public: r.x25519Public,
    x25519Derive: r.x25519Derive,
    aliasRoot: r.aliasRoot,
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
