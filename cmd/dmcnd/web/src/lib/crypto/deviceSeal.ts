// Sealing what this device keeps about an account, so it is unreadable while the account is locked.
//
// Two things use it: the search index (lib/search/indexStore.ts) and the list-row cache
// (api/previewCache.ts). Both are caches of mail the relay already holds, kept here so an unlock
// does not start from nothing, and both hold what that mail says. So each is AES-GCM under a key
// HKDF-derived from WorkingKeys.aliasRoot: a handle that exists only while the account is unlocked,
// and one the derivation cannot turn back into the seed. The salt names the purpose, so the two
// caches (and the alias keypairs derived from the same root) share no key.
//
// Every record is sealed with its own storage key as the associated data: a record moved to
// another slot, or copied from another account, fails to open rather than being read as the wrong
// thing.

import { idbDeletePrefix, idbGet, idbPutMany } from './idb';
import { bufferSource } from './bytes';

export interface Sealed { iv: Uint8Array; ct: ArrayBuffer }

const enc = new TextEncoder();

/** The device-local key for one purpose of one account. */
export async function deriveDeviceKey(root: CryptoKey, address: string, purpose: string): Promise<CryptoKey> {
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: bufferSource(enc.encode(`dmcn-${purpose}-v1`)),
      info: bufferSource(enc.encode(address.trim().toLowerCase())),
    },
    root,
    256,
  ));
  try {
    return await crypto.subtle.importKey('raw', bufferSource(bits), 'AES-GCM', false, ['encrypt', 'decrypt']);
  } finally {
    bits.fill(0);
  }
}

export async function seal(key: CryptoKey, slot: string, plain: Uint8Array): Promise<Sealed> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bufferSource(iv), additionalData: bufferSource(enc.encode(slot)) },
    key,
    bufferSource(plain),
  );
  return { iv, ct };
}

export async function unseal(key: CryptoKey, slot: string, s: Sealed): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bufferSource(s.iv), additionalData: bufferSource(enc.encode(slot)) },
    key,
    s.ct,
  ));
}

interface Meta { v: number; check: Sealed }
const CHECK = enc.encode('dmcn-device-seal');

/**
 * Whether what is stored under prefix was written with this key (and this layout version). When it
 * was not (the account re-keyed, or the layout changed), everything under prefix is deleted and a
 * fresh marker written: these are caches, and what they cached comes back from the relay.
 *
 * Returns true when the stored contents can be used.
 */
export async function keepIfOpens(store: string, prefix: string, key: CryptoKey, version: number): Promise<boolean> {
  const meta = await idbGet<Meta>(store, prefix + 'meta');
  if (meta && meta.v === version) {
    try {
      await unseal(key, prefix + 'meta', meta.check);
      return true;
    } catch { /* a different key: start again */ }
  }
  await idbDeletePrefix(store, prefix);
  const fresh: Meta = { v: version, check: await seal(key, prefix + 'meta', CHECK) };
  await idbPutMany(store, [[prefix + 'meta', fresh]]);
  return false;
}
