// Working-handle lifetime policy.
//
// An unlocked working handle should live exactly as long as the tab session that
// created it: survive a page refresh, but be gone once the tab/browser is closed
// (so reopening requires a passkey/password, not one click). sessionStorage has
// precisely that lifetime, so we mint a per-tab id there and key the handle by it.
// When the tab closes, the id is gone, the handle is orphaned (and later GC'd), and
// re-unlock is required — no heartbeat or timing window needed.
//
// Handles are keyed by tab AND account, so one tab can hold SEVERAL accounts
// unlocked at once (the header's account switcher moves between them without a
// re-prompt) while closing that tab still locks every one of them together.
// Holding N unlocked handles does widen what an XSS on the origin could *use* —
// it still can't steal them (they stay non-extractable, and the raw-bytes paths in
// crypto/reauth.ts re-derive from the encrypted keystore instead of reading these).
//
// "Stay signed in" (opt-in) instead keys the handle by account address alone, so it
// persists across browser restarts for one-click access.

import { storageKey } from './appContext';
import { randomHex } from './crypto/bytes';

// Namespaced per context (see appContext.storageKey): an installed app and a browser
// tab are separate devices to their user, so turning on "stay signed in" in one must
// not extend key lifetime in the other. TAB_KEY needs no namespacing — sessionStorage
// is per-window already, so the two never shared it.
const STAY_KEY = storageKey('dmcn_stay_signed_in');
const TAB_KEY = 'dmcn_tab_id';

export function isStaySignedIn(): boolean {
  try { return localStorage.getItem(STAY_KEY) === 'true'; } catch { return false; }
}

export function setStaySignedIn(on: boolean): void {
  try { localStorage.setItem(STAY_KEY, on ? 'true' : 'false'); } catch { /* ignore */ }
}

function randomId(): string {
  return randomHex(16);
}

// getTabId returns this tab's stable id (created on first use). It lives in
// sessionStorage: it survives a reload but vanishes when the tab/browser closes.
export function getTabId(): string {
  try {
    let id = sessionStorage.getItem(TAB_KEY);
    if (!id) { id = randomId(); sessionStorage.setItem(TAB_KEY, id); }
    return id;
  } catch {
    return 'no-session-storage';
  }
}

// workingKeyRef is the IndexedDB key under which this tab's working handle for
// `address` is stored. Default (lock-on-close): per-tab AND per-account, so a tab
// can hold several unlocked accounts and closing it orphans all of them at once.
// "Stay signed in": per-account only, persisting across browser restarts.
// Addresses are local@domain and carry no colon, so `tab:<id>:<address>` splits
// unambiguously back into its two parts (see parseTabWorkingRef).
export function workingKeyRef(address: string): string {
  return isStaySignedIn() ? `acct:${address}` : `tab:${getTabId()}:${address}`;
}

// tabWorkingPrefix is the key prefix owned by this tab in the lock-on-close posture.
export function tabWorkingPrefix(): string {
  return `tab:${getTabId()}:`;
}

// parseTabWorkingRef splits a per-tab handle key into its tab id and account. A
// legacy single-slot key ('tab:<id>', pre-multi-account) yields a null address.
export function parseTabWorkingRef(key: string): { tabId: string; address: string | null } | null {
  if (!key.startsWith('tab:')) return null;
  const rest = key.slice('tab:'.length);
  const sep = rest.indexOf(':');
  if (sep < 0) return { tabId: rest, address: null };
  return { tabId: rest.slice(0, sep), address: rest.slice(sep + 1) };
}

// Presence: each open tab writes a heartbeat under its own localStorage key so GC can
// tell a still-open tab from a closed-tab orphan. This does NOT gate the lock
// decision (that's exact via the per-tab sessionStorage id) — it only lets a freshly
// opened tab promptly sweep handles whose tab is gone, instead of leaving them to age
// out. Each tab owns its key (no shared-map write races); stale keys are pruned on read.
const PRESENCE_PREFIX = storageKey('dmcn_tab_');
const PRESENCE_INTERVAL_MS = 20_000;
const PRESENCE_STALE_MS = 120_000; // > background setInterval throttling (~60s)

export function startPresence(): () => void {
  const key = PRESENCE_PREFIX + getTabId();
  const beat = () => { try { localStorage.setItem(key, String(Date.now())); } catch { /* ignore */ } };
  beat();
  const id = window.setInterval(beat, PRESENCE_INTERVAL_MS);
  return () => { window.clearInterval(id); };
}

// liveTabIds returns the ids of currently-open tabs (fresh heartbeat), pruning stale
// entries as it scans.
export function liveTabIds(): Set<string> {
  const live = new Set<string>();
  try {
    const now = Date.now();
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      if (!key || !key.startsWith(PRESENCE_PREFIX)) continue;
      const ts = Number(localStorage.getItem(key));
      if (Number.isFinite(ts) && now - ts < PRESENCE_STALE_MS) live.add(key.slice(PRESENCE_PREFIX.length));
      else localStorage.removeItem(key);
    }
  } catch { /* ignore */ }
  return live;
}
