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

import { fromBase64, toBase64 } from './crypto/keys';
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
  bothWorkingRefs,
  handleStorageVerdict,
  rememberLiveHandles,
  liveHandles,
  liveAddresses,
  forgetLiveHandles,
} from './crypto/workingKeys';
import { requestPersistentStorage } from './crypto/storage';
import { WORKING_STORE, idbGet, idbGetAllKeys } from './crypto/idb';
import { scopeIdFor, tearDownScope } from './push/scopes';
import { forgetEndpoint } from './push/subscription';
import { detachAccount } from './crypto/deviceKeystore';
import { workingKeyRef } from './sessionLifetime';
import { storageKey } from './appContext';

export interface DeviceAccount {
  address: string;
  // The encrypted keystore, or null for an account that is unlocked in this tab but
  // has no at-rest copy (a temporary session) — it can be used until the tab closes
  // but can never be re-unlocked, so it is never offered an "Unlock" affordance.
  ks: LocalKeystore | null;
  unlocked: boolean;
}

// The account this context was last acting as.
//
// Device-local and not a secret: every address here is already listed in the clear while the
// accounts are locked, which is what the picker shows. It exists so an unlock that opens SEVERAL
// mailboxes at once can land on the one the person actually uses, instead of alphabetically.
//
// localStorage rather than IndexedDB beside the handles: losing it costs one wrong landing, so the
// durability the keys need would be spent on nothing.
const LAST_ACCOUNT_KEY = 'dmcn_last_account';

export function rememberLastAccount(address: string): void {
  try { localStorage.setItem(storageKey(LAST_ACCOUNT_KEY), address); } catch { /* ignore */ }
}

export function lastAccount(): string | null {
  try { return localStorage.getItem(storageKey(LAST_ACCOUNT_KEY)); } catch { return null; }
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
  // Accounts this page unlocked but the store may not have kept. Without these, an unlock whose
  // write failed would list its accounts as locked while they are open and usable.
  for (const address of liveAddresses()) {
    if (!byAddress.has(address)) byAddress.set(address, { address, ks: null, unlocked: false });
  }
  await Promise.all([...byAddress.values()].map(async account => {
    account.unlocked = (await loadUnlockedKeys(account.address, account.ks)) !== null;
  }));
  return [...byAddress.values()]
    .filter(a => a.ks !== null || a.unlocked)
    .sort((a, b) => a.address.localeCompare(b.address));
}

/**
 * Why a just-written handle cannot be read back, or null if it can.
 *
 * loadUnlockedKeys answers the same question with a boolean and DELETES what it rejects, which is
 * right for a routine restore and useless for diagnosis. loadWorkingKeys is no better here: it
 * swallows a failed READ into the same null as a missing value, so a write that committed and a
 * read that threw are indistinguishable — which is how "the browser stored nothing under its key"
 * was reported for a key that may well have been stored.
 *
 * So this goes to the store directly, separates the cases, and when the value really is absent
 * says what the store DOES hold. That last part is the decisive one: a committed write whose value
 * is not there afterwards is either under a different key (which the listing shows) or was never
 * durable (which an empty listing shows). Nothing here deletes anything.
 *
 * Written for several accounts unlocking together on WebKit, where every one but the account held
 * in memory came back unusable and nothing said why.
 */
export async function describeHandle(address: string): Promise<string | null> {
  const ref = workingKeyRef(address);
  let wk: WorkingKeys | undefined;
  try {
    wk = await idbGet<WorkingKeys>(WORKING_STORE, ref);
  } catch (e) {
    return `reading it back threw ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`;
  }
  if (!wk) {
    let keys: string[];
    try {
      keys = await idbGetAllKeys(WORKING_STORE);
    } catch (e) {
      return `nothing came back for "${ref}" and the store could not be listed (${e instanceof Error ? e.name : 'unknown'})`;
    }
    if (!keys.includes(ref)) {
      return `nothing stored at "${ref}" — the store holds: ${keys.join(', ') || 'nothing at all'}`;
    }
    // The key is there and its value is not. That is a browser that serialised a record it cannot
    // revive — IndexedDB answers an unrevivable value with undefined rather than an error, which is
    // why every layer above this reported it as "nothing stored". The row can never be read, so it
    // is removed rather than left to accumulate, and the probe says which key type broke.
    await clearWorkingKeys(ref);
    return `the browser stored "${ref}" but cannot read it back (its key is in the store, its value `
      + `is not) — it has been removed. Key storage here: ${(await handleStorageVerdict()).detail}`;
  }
  if (wk.address !== address) return `the stored handle names ${wk.address || 'no account'}`;
  if (!wk.aliasRoot) return 'the browser returned the key set without its derivation root';
  if (!(wk.ed25519Public instanceof Uint8Array)) {
    return `the stored public key came back as ${Object.prototype.toString.call(wk.ed25519Public)}`;
  }
  const record = await loadLocalKeystore(address);
  if (record && toBase64(wk.ed25519Public) !== record.ed25519Public) {
    return 'the stored public key does not match its keystore';
  }
  return null;
}

// loadUnlockedKeys returns this session's working handles for `address`, or null if
// the account isn't unlocked here. It applies the same safety checks the key context
// uses on restore: a handle must name its own account, and (when an encrypted
// keystore exists) match its public key — a stale one is dropped rather than used,
// so a re-imported identity can never be signed for with the old key.
export async function loadUnlockedKeys(address: string, ks?: LocalKeystore | null): Promise<WorkingKeys | null> {
  // Unlocked in this page is unlocked, whether or not the store kept a copy. Checked before the
  // round trip, so the common case is also the fast one.
  const held = liveHandles(address);
  if (held) return held;
  const ref = workingKeyRef(address);
  const wk = await loadWorkingKeys(ref);
  if (!wk || wk.address !== address) return null;
  const record = ks === undefined ? await loadLocalKeystore(address) : ks;
  if (record && toBase64(wk.ed25519Public) !== record.ed25519Public) {
    await clearWorkingKeys(ref);
    return null;
  }
  // A handle persisted before the KDF root existed cannot derive anything; one re-unlock
  // imports a complete set, and that beats a feature that silently does not work.
  if (!wk.aliasRoot) {
    await clearWorkingKeys(ref);
    return null;
  }
  return wk;
}

// persistWorkingKeys stores freshly-imported handles under this session's ref. The
// single place that knows the ref policy — both the key context and the account
// switcher go through it.
export async function persistWorkingKeys(wk: WorkingKeys): Promise<void> {
  // This page knows the account is unlocked whatever the store does with it. Recorded FIRST and
  // unconditionally, so a write that fails costs a reload rather than a mailbox.
  rememberLiveHandles(wk);
  // On a browser that cannot read a handle back, writing one achieves nothing except a row that
  // can never be used — and, before this, a pile of them. The unlock still works; it just does not
  // survive a reload here, which canKeepUnlocked() lets the UI say instead of re-discovering.
  if (!(await handleStorageVerdict()).ok) return;
  await saveWorkingKeys(workingKeyRef(wk.address), wk);
  // The local keystore is the only at-rest copy, so ask the browser to exempt this
  // origin from storage eviction (best-effort; the export backup is the real net).
  void requestPersistentStorage();
}

// forgetAccount removes an identity from this browser: the encrypted keystore plus
// any handle it may hold under either posture's ref.
//
// It also turns this account's notifications off, and it is the ONE act besides the settings card
// that does. Signing out deliberately leaves them running, but removal is different: the card lives
// behind an unlocked session, so once the keystore is gone there would be no way left to stop the
// device buzzing for mail nobody here can read. No keys are needed for it either — dropping the
// subscription kills the endpoint, and the relay deletes its row the first time a wake-up to a dead
// endpoint is refused.
export async function forgetAccount(address: string): Promise<void> {
  const ks = await loadLocalKeystore(address);
  if (ks) {
    try {
      await tearDownScope(await scopeIdFor(fromBase64(ks.x25519Public)));
    } catch {
      // Never block removal on it. The subscription lapses on its own once the relay's rows expire.
    }
  }
  forgetEndpoint(address);
  // And out of this device's shared unlock, if it was attached: leaving it there would keep a copy
  // of the keys the rest of this function is removing.
  await detachAccount(address);
  forgetLiveHandles(address);
  for (const ref of bothWorkingRefs(address)) await clearWorkingKeys(ref);
  await clearLocalKeystore(address);
  // An account that is gone cannot be the one to land in.
  if (lastAccount() === address) {
    try { localStorage.removeItem(storageKey(LAST_ACCOUNT_KEY)); } catch { /* ignore */ }
  }
}

/**
 * Whether an unlock on this browser survives a reload.
 *
 * False on a browser that cannot read a stored handle back — WebKit, for the X25519 key a handle
 * needs to decrypt anything, which is not a key it can do without. Accounts still unlock and still
 * work; they simply have to be unlocked again after a reload. Worth saying once, plainly, rather
 * than leaving someone to notice their accounts keep re-locking.
 */
export async function canKeepUnlocked(): Promise<boolean> {
  return (await handleStorageVerdict()).ok;
}
