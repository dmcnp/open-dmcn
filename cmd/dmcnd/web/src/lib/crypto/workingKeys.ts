// Working keys: the unlocked identity keys as NON-EXTRACTABLE CryptoKey handles,
// persisted in IndexedDB. The private key bytes never sit in a JS-reachable string
// (unlike the old sessionStorage 'dmcn_keys' blob), so an XSS on the origin has
// nothing to exfiltrate — it can still *call* sign/deriveBits while the page is open
// (use, not theft), which the CSP/SRI hardening is there to shrink.
//
// importEd25519PrivateKey / importX25519PrivateKey already import with
// extractable=false, so the handles cannot be exported back to raw bytes. Operations
// that genuinely need raw bytes (pairing-out, export) re-derive them transiently from
// the encrypted keystore via reauth.ts — they do not read these handles.

import type { IdentityKeyPair } from './keys';
import { importEd25519PrivateKey, importX25519PrivateKey } from './keys';
import { bufferSource } from './bytes';
import { DEVICE_STORE, WORKING_STORE, idbGet, idbGetAllKeys, idbPut, idbDelete } from './idb';
import { accountWorkingRef, tabWorkingPrefix, parseTabWorkingRef, workingKeyRef } from '../sessionLifetime';
import { isLockOnLeave } from '../devicePosture';

export interface WorkingKeys {
  ed25519Sign: CryptoKey;     // non-extractable, ['sign']
  x25519Derive: CryptoKey;    // non-extractable, ['deriveBits']
  ed25519Public: Uint8Array;  // 32 bytes (public, non-secret)
  x25519Public: Uint8Array;   // 32 bytes (public, non-secret)
  deviceId: Uint8Array;       // 16 bytes
  createdAt: number;          // Unix seconds
  address: string;            // owning account (validates the handle matches the session)
  // The account seed imported as a non-extractable HKDF root, ['deriveBits'] only. A
  // deployment that derives further keys from the account (per-address throwaway keypairs,
  // say) derives them from this handle rather than from the seed, which is gone by the time
  // anything asks: the seed never sits in JS after import, and the handle can only produce
  // OUTPUTS of the KDF, never the seed itself. Absent on handles persisted by an older client;
  // loadUnlockedKeys treats such a handle as stale.
  aliasRoot?: CryptoKey;
}

// Handles are keyed by a session ref (see sessionLifetime.workingKeyRef): per-tab
// AND per-account ('tab:<id>:<addr>') by default so they die with the tab, or
// per-account ('acct:<addr>') for stay-signed-in. Either way a tab may hold several
// accounts unlocked at once; the address field lets a reader reject a handle that
// belongs to a different account than the one it asked for.

/**
 * Whether this browser can store a working handle and read it back.
 *
 * Not a theoretical question. WebKit serialises a record holding these keys, persists its key, and
 * then answers a read with `undefined` — IndexedDB's way of reporting a value it cannot revive. So
 * the write reports success, the row exists, and the handle is gone. Everything above reads that as
 * "nothing stored", which is exactly as misleading as it sounds.
 *
 * Measured the way the app actually builds a handle: the same importEd25519PrivateKey /
 * importX25519PrivateKey / HKDF calls over random bytes, stored as one record like a real one.
 * Testing them individually as well says WHICH type a browser chokes on, which is the difference
 * between "persist a reduced handle" and "this browser cannot keep an unlock at all".
 *
 * Throwaway keys under their own prefix, deleted afterwards. Nothing of any account's goes near it.
 */
export interface HandleStorageVerdict {
  /** Whether a COMPLETE handle survives a round trip. Only that is worth persisting. */
  ok: boolean;
  /** Per key type, for a report worth reading: `ed25519=ok x25519=unreadable …`. */
  detail: string;
}

async function roundTrips(ref: string, value: Record<string, unknown>): Promise<string> {
  try {
    await idbPut(WORKING_STORE, ref, value);
    const back = await idbGet<Record<string, unknown>>(WORKING_STORE, ref);
    if (back === undefined) return 'unreadable';
    for (const k of Object.keys(value)) if (!back[k]) return `dropped ${k}`;
    return 'ok';
  } catch (e) {
    return e instanceof Error ? e.name : 'threw';
  } finally {
    try { await idbDelete(WORKING_STORE, ref); } catch { /* best effort */ }
  }
}

export async function probeHandleStorage(): Promise<HandleStorageVerdict> {
  const raw = () => crypto.getRandomValues(new Uint8Array(32));
  let ed: CryptoKey, x: CryptoKey, hkdf: CryptoKey;
  try {
    ed = await importEd25519PrivateKey(raw());
    x = await importX25519PrivateKey(raw());
    hkdf = await crypto.subtle.importKey('raw', bufferSource(raw()), 'HKDF', false, ['deriveBits']);
  } catch (e) {
    // The keys cannot even be made here, which is a different and much larger problem.
    return { ok: false, detail: `could not import test keys (${e instanceof Error ? e.name : 'unknown'})` };
  }
  const parts = [
    `ed25519=${await roundTrips('probe:ed25519', { key: ed })}`,
    `x25519=${await roundTrips('probe:x25519', { key: x })}`,
    `hkdf=${await roundTrips('probe:hkdf', { key: hkdf })}`,
  ];
  // The one that decides it: a handle is only useful whole.
  const whole = await roundTrips('probe:whole', { ed25519Sign: ed, x25519Derive: x, aliasRoot: hkdf });
  parts.push(`whole-handle=${whole}`);
  return { ok: whole === 'ok', detail: parts.join(' ') };
}

// The verdict, taken once per context and remembered. Probing costs four transactions, and the
// answer is a property of the browser rather than of any account.
let verdict: HandleStorageVerdict | null = null;

export async function handleStorageVerdict(): Promise<HandleStorageVerdict> {
  if (verdict) return verdict;
  try {
    const stored = await idbGet<HandleStorageVerdict>(DEVICE_STORE, HANDLE_STORAGE_KEY);
    if (stored && typeof stored.ok === 'boolean') return (verdict = stored);
  } catch { /* fall through and measure */ }
  const measured = await probeHandleStorage();
  verdict = measured;
  try { await idbPut(DEVICE_STORE, HANDLE_STORAGE_KEY, measured); } catch { /* it will be remeasured */ }
  return measured;
}

const HANDLE_STORAGE_KEY = 'handle-storage';

// The accounts unlocked in THIS page, held in memory.
//
// IndexedDB is how an unlocked account survives a reload; it is not how the app knows which
// accounts are open right now. Those are two different questions, and conflating them meant a
// write that did not stick cost the user an account they had just unlocked — silently, because
// nothing reads back what it stores. On a platform where persisting several handles in quick
// succession proved unreliable, that turned "one unlock opens all your mailboxes" into "one
// unlock opens one mailbox".
//
// So the page keeps its own answer. Persistence is still attempted and still preferred on restore
// — it is what makes a refresh free — but losing it now costs a reload, not a mailbox.
//
// These are the same non-extractable CryptoKey handles that would otherwise sit in IndexedDB, for
// the lifetime of one page rather than indefinitely. Nothing raw, and nothing new is reachable:
// holding several unlocked accounts at once is what the account switcher has always done.
const livePage = new Map<string, WorkingKeys>();

export function rememberLiveHandles(wk: WorkingKeys): void {
  if (wk.address) livePage.set(wk.address, wk);
}

export function liveHandles(address: string): WorkingKeys | null {
  const wk = livePage.get(address);
  return wk && wk.address === address ? wk : null;
}

export function liveAddresses(): string[] {
  return [...livePage.keys()];
}

export function forgetLiveHandles(address: string): void {
  livePage.delete(address);
}

export function forgetAllLiveHandles(): void {
  livePage.clear();
}

// importWorkingKeys turns a freshly-decrypted raw key pair into non-extractable
// handles for `address`. The caller discards the raw IdentityKeyPair afterwards.
export async function importWorkingKeys(address: string, kp: IdentityKeyPair): Promise<WorkingKeys> {
  const seed = kp.ed25519Private.slice(0, 32);
  const [ed25519Sign, x25519Derive, aliasRoot] = await Promise.all([
    importEd25519PrivateKey(seed),
    importX25519PrivateKey(kp.x25519Private),
    crypto.subtle.importKey('raw', bufferSource(seed), 'HKDF', false, ['deriveBits']),
  ]);
  return {
    ed25519Sign,
    x25519Derive,
    aliasRoot,
    ed25519Public: kp.ed25519Public,
    x25519Public: kp.x25519Public,
    deviceId: kp.deviceId,
    createdAt: kp.createdAt,
    address,
  };
}

export async function saveWorkingKeys(ref: string, wk: WorkingKeys): Promise<void> {
  // CryptoKey objects are structured-cloneable; the private bytes never serialize.
  await idbPut(WORKING_STORE, ref, wk);
}

export async function loadWorkingKeys(ref: string): Promise<WorkingKeys | null> {
  try {
    const wk = await idbGet<WorkingKeys>(WORKING_STORE, ref);
    return wk ?? null;
  } catch {
    return null;
  }
}

export async function clearWorkingKeys(ref: string): Promise<void> {
  try {
    await idbDelete(WORKING_STORE, ref);
  } catch {
    /* ignore */
  }
}

// gcWorkingHandles removes handles no longer referenceable: per-tab handles whose tab
// is no longer open (its id isn't in the live set — a closed-tab orphan), and any
// legacy/unknown keys. Orphans are
// non-extractable and unreferenceable, but removing them promptly (the moment any tab
// opens after a browser close) shrinks the XSS-reachable residual to near zero.
//
// It also re-keys a legacy single-slot handle ('tab:<id>', from before a tab could
// hold several accounts) to 'tab:<id>:<address>' when its tab is still open, so
// upgrading the app doesn't sign the open tab out. CryptoKey handles are
// structured-cloneable, so this is a plain copy — no key material is exposed.
//
// What it deliberately no longer does is delete PERSISTENT handles because a preference says to.
// It used to drop every 'acct:' row whenever stay-signed-in read false — and that flag lived in
// localStorage while the handles lived here, so on a browser that clears the first and keeps the
// second (Safari, mobile Chrome) an evaporated preference destroyed working keys and left every
// account but one locked. A deletion has to follow from an ACT: signing out, removing the account,
// the app locking, or the posture being changed. Never from a preference that is merely missing.
export async function gcWorkingHandles(liveTabIds: Set<string>): Promise<void> {
  try {
    const keys = await idbGetAllKeys(WORKING_STORE);
    await Promise.all(keys.map(async k => {
      const tabRef = parseTabWorkingRef(k);
      if (tabRef) {
        if (!liveTabIds.has(tabRef.tabId)) { await idbDelete(WORKING_STORE, k); return; }
        if (tabRef.address === null) {
          const wk = await loadWorkingKeys(k);
          if (wk?.address) await idbPut(WORKING_STORE, `tab:${tabRef.tabId}:${wk.address}`, wk);
          await idbDelete(WORKING_STORE, k);
        }
      } else if (k.startsWith('acct:')) {
        // Persistent by request. Left alone here on purpose — see the note above.
      } else {
        await idbDelete(WORKING_STORE, k); // legacy 'identity' / unknown
      }
    }));
  } catch {
    /* ignore */
  }
}

// listUnlockedRefs returns the handles this tab can currently reach, one per account:
// its own 'tab:<id>:<addr>' rows in the default posture, or every 'acct:<addr>' row
// when locking on leave is off. The account switcher uses it to tell unlocked accounts
// from locked ones — including an account with no encrypted keystore (a temporary
// pairing session), which exists only as a working handle.
export async function listUnlockedRefs(): Promise<Array<{ ref: string; address: string }>> {
  try {
    const prefix = isLockOnLeave() ? tabWorkingPrefix() : 'acct:';
    const keys = await idbGetAllKeys(WORKING_STORE);
    return keys
      .filter(k => k.startsWith(prefix))
      .map(k => ({ ref: k, address: k.slice(prefix.length) }))
      .filter(r => r.address !== '');
  } catch {
    return [];
  }
}

// clearUnlockedHandles locks every account this tab holds (sign out of all, and the app lock).
// Both halves: the stored handles and the ones this page is holding.
export async function clearUnlockedHandles(): Promise<void> {
  forgetAllLiveHandles();
  const refs = await listUnlockedRefs();
  await Promise.all(refs.map(r => clearWorkingKeys(r.ref)));
}

/**
 * Move every handle this tab holds to the ref the CURRENT posture reads from.
 *
 * Without this, changing the posture silently locks every open account: the switch only changes
 * which key workingKeyRef() returns, so live handles stay where they were while the next read
 * looks in the other place and finds nothing. That was true in both directions — turning
 * persistence on stranded the tab's handles, and turning it off left them for the collector.
 *
 * Call it AFTER devicePosture.setLockOnLeave, so workingKeyRef already answers the new way.
 */
export async function applyLockPosture(): Promise<void> {
  const from = isLockOnLeave() ? 'acct:' : tabWorkingPrefix();
  try {
    for (const key of await idbGetAllKeys(WORKING_STORE)) {
      if (!key.startsWith(from)) continue;
      const address = key.slice(from.length);
      if (!address) continue;
      const wk = await loadWorkingKeys(key);
      // A handle that cannot be read, or that names another account, is not one to carry over.
      if (!wk || wk.address !== address) continue;
      await idbPut(WORKING_STORE, workingKeyRef(address), wk);
      await idbDelete(WORKING_STORE, key);
    }
  } catch {
    // The posture still changed; at worst an account reads as locked and is unlocked again.
  }
}

/** Both refs an account could hold a handle under. Removing an account has to clear each. */
export function bothWorkingRefs(address: string): string[] {
  return [workingKeyRef(address), accountWorkingRef(address)];
}
