// What this context does with unlocked keys when you leave it.
//
// One setting, "lock when I leave", ON by default: working handles are held only for as long as
// the app is in front of you, and coming back takes an unlock. Off, they persist across restarts
// for one-click access. It is the same choice the old "stay signed in" switch made, said the way
// round that matches what it protects.
//
// It lives in IndexedDB, beside the handles it governs. That is the whole point of this module
// rather than a localStorage line: the collector used to DELETE every persistent handle whenever
// the preference read false, and the preference lived in a store that Safari and mobile Chrome
// clear far more eagerly than the one holding the handles. A preference that can evaporate on its
// own must never be the reason keys are destroyed — so the posture sits in the same durability
// domain as the keys, and its absence now means "unknown, assume the safe default" rather than
// "the user turned persistence off".
//
// Read SYNCHRONOUSLY everywhere, because workingKeyRef() is on every path that touches a handle.
// The value is loaded once before the app renders (init below) and cached here; localStorage is
// kept only as a mirror, for the case where IndexedDB is unreachable at all.

import { DEVICE_STORE, idbGet, idbPut } from './crypto/idb';
import { storageKey } from './appContext';

interface Posture {
  lockOnLeave: boolean;
}

const KEY = 'posture';
// Namespaced per context (appContext.storageKey): an installed app and a browser tab are separate
// devices to their user, so the two keep separate postures. IndexedDB already separates them by
// database name; this is only for the mirror.
const MIRROR_KEY = storageKey('dmcn_lock_on_leave');

// ON unless someone has said otherwise. The safe direction: the worst a wrong default can do here
// is ask for an unlock that was not needed.
let cached = true;
let loaded = false;

/**
 * Load the stored posture into the synchronous cache.
 *
 * Called from main.tsx before the app renders, so nothing can read a stale default and write a
 * handle under the wrong ref. Falls back to the mirror, then to the default.
 */
export async function initDevicePosture(): Promise<void> {
  if (loaded) return;
  loaded = true;
  try {
    const stored = await idbGet<Posture>(DEVICE_STORE, KEY);
    if (stored && typeof stored.lockOnLeave === 'boolean') {
      cached = stored.lockOnLeave;
      return;
    }
  } catch { /* fall through to the mirror */ }
  try {
    const mirror = localStorage.getItem(MIRROR_KEY);
    if (mirror !== null) cached = mirror === 'true';
  } catch { /* the default stands */ }
}

/** Whether this context locks when you leave it. */
export function isLockOnLeave(): boolean {
  return cached;
}

/**
 * Record the choice. Takes effect immediately for every synchronous reader.
 *
 * Callers that hold unlocked accounts must re-key their handles for the new posture — see
 * sessionLifetime.applyLockPosture, which is what keeps a live account from reading as locked the
 * instant the switch is flipped.
 */
export async function setLockOnLeave(next: boolean): Promise<void> {
  cached = next;
  loaded = true;
  try { localStorage.setItem(MIRROR_KEY, next ? 'true' : 'false'); } catch { /* mirror is optional */ }
  await idbPut(DEVICE_STORE, KEY, { lockOnLeave: next } satisfies Posture);
}

// Legacy: the posture used to live here alone, under its old name and inverted sense.
const LEGACY_STAY_KEY = storageKey('dmcn_stay_signed_in');

/**
 * Carry a pre-existing "stay signed in" choice over, once.
 *
 * Only an explicit `true` is carried: someone who turned persistence ON said something, and losing
 * that would lock them out of a posture they chose. An absent or false value says nothing worth
 * keeping — false WAS the default, and it is also what an evaporated preference looks like.
 */
export async function migrateLegacyPosture(): Promise<void> {
  try {
    const legacy = localStorage.getItem(LEGACY_STAY_KEY);
    if (legacy === null) return;
    localStorage.removeItem(LEGACY_STAY_KEY);
    if (legacy !== 'true') return;
    if ((await idbGet<Posture>(DEVICE_STORE, KEY)) !== undefined) return; // already chosen since
    await setLockOnLeave(false);
  } catch { /* the default stands, which is the safe direction */ }
}
