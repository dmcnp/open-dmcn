// The set of identities this browser knows about, and the persistence policy for
// their unlocked handles. Two independent sources feed it:
//
//   - the encrypted keystores (IndexedDB, one per address) — an account that can be
//     UNLOCKED here, whether or not it currently is;
//   - this tab's working handles — an account that IS unlocked right now.
//
// They're a union, not a hierarchy: a temporary (single-use pairing) session writes
// no keystore on purpose, so it exists only as a handle — listing both is what keeps
// it reachable in the account switcher instead of stranding it.

import { toBase64 } from './crypto/keys';
import {
  listLocalKeystores,
  loadLocalKeystore,
  clearLocalKeystore,
  type LocalKeystore,
} from './crypto/localKeystore';
import {
  type WorkingKeys,
  loadWorkingKeys,
  saveWorkingKeys,
  clearWorkingKeys,
  listUnlockedRefs,
} from './crypto/workingKeys';
import { requestPersistentStorage } from './crypto/storage';
import { workingKeyRef } from './sessionLifetime';

export interface DeviceAccount {
  address: string;
  // The encrypted keystore, or null for an account that is unlocked in this tab but
  // has no at-rest copy (a temporary session) — it can be used until the tab closes
  // but can never be re-unlocked, so it is never offered an "Unlock" affordance.
  ks: LocalKeystore | null;
  unlocked: boolean;
}

export function initialsOf(address: string): string {
  const local = address.split('@')[0] || address;
  return local.slice(0, 2).toUpperCase();
}

// listDeviceAccounts enumerates every account reachable from this browser session,
// sorted by address.
//
// "Unlocked" is decided by actually loading the handle, not by seeing a key with the
// right name. The two are not the same: a handle can sit at the expected ref and still
// be unusable — naming another account, or holding a key the keystore no longer
// matches after a re-import — and the switch would then reject it and fall back to a
// passkey/password prompt on a row that just said "Unlocked". Same check, one answer.
// It also self-heals, since loadUnlockedKeys drops a stale handle as it finds it.
export async function listDeviceAccounts(): Promise<DeviceAccount[]> {
  const [keystores, refs] = await Promise.all([listLocalKeystores(), listUnlockedRefs()]);
  const byAddress = new Map<string, DeviceAccount>();
  for (const ks of keystores) {
    byAddress.set(ks.address, { address: ks.address, ks, unlocked: false });
  }
  for (const r of refs) {
    // A handle with no keystore is a temporary (single-use) session: it exists only
    // while unlocked, so it earns a row only if the check below passes.
    if (!byAddress.has(r.address)) byAddress.set(r.address, { address: r.address, ks: null, unlocked: false });
  }
  await Promise.all(refs.map(async r => {
    const account = byAddress.get(r.address);
    if (account) account.unlocked = (await loadUnlockedKeys(r.address, account.ks)) !== null;
  }));
  return [...byAddress.values()]
    .filter(a => a.ks !== null || a.unlocked)
    .sort((a, b) => a.address.localeCompare(b.address));
}

// loadUnlockedKeys returns this session's working handles for `address`, or null if
// the account isn't unlocked here. It applies the same safety checks the key context
// uses on restore: a handle must name its own account, and (when an encrypted
// keystore exists) match its public key — a stale one is dropped rather than used,
// so a re-imported identity can never be signed for with the old key.
export async function loadUnlockedKeys(address: string, ks?: LocalKeystore | null): Promise<WorkingKeys | null> {
  const ref = workingKeyRef(address);
  const wk = await loadWorkingKeys(ref);
  if (!wk || wk.address !== address) return null;
  const record = ks === undefined ? await loadLocalKeystore(address) : ks;
  if (record && toBase64(wk.ed25519Public) !== record.ed25519Public) {
    await clearWorkingKeys(ref);
    return null;
  }
  return wk;
}

// persistWorkingKeys stores freshly-imported handles under this session's ref. The
// single place that knows the ref policy — both the key context and the account
// switcher go through it.
export async function persistWorkingKeys(wk: WorkingKeys): Promise<void> {
  await saveWorkingKeys(workingKeyRef(wk.address), wk);
  // The local keystore is the only at-rest copy, so ask the browser to exempt this
  // origin from storage eviction (best-effort; the export backup is the real net).
  void requestPersistentStorage();
}

// forgetAccount removes an identity from this browser: the encrypted keystore plus
// any handle it may hold under either posture's ref.
export async function forgetAccount(address: string): Promise<void> {
  await clearWorkingKeys(workingKeyRef(address));
  await clearWorkingKeys(`acct:${address}`);
  await clearLocalKeystore(address);
}
