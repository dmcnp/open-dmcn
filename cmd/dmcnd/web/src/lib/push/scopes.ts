// One service worker registration per account, so one device can be notified for several
// mailboxes and each wake-up says which.
//
// A browser gives one push subscription per service worker REGISTRATION, not per origin. So the
// way to get an endpoint per account is to register the same worker script under a scope of its
// own for each account. A root-level script may claim any narrower scope with no
// `Service-Worker-Allowed` header, and the scope URL is never fetched — it is a name, not a page.
//
// The name is derived from the account's X25519 public key, which is the mailbox key the relay
// keys everything by (`rxHex`). That choice does three jobs at once:
//
//   - Aliases come free. A shared alias IS the account's own keypair under another name, and an
//     isolated throwaway is merged into the canonical mailbox at ingest, so every address an
//     account holds already lands on this one key. One scope covers all of them.
//   - It works while the account is LOCKED. The keystore stores the public half in the clear, so a
//     wake-up can be matched to an account that has not been unlocked — which is the common case
//     for a closed app — with no index to keep in sync.
//   - The installed app and the browser tab converge on it. They are separate keystores but ONE
//     service worker registry, so a random id would give one account two scopes, two subscriptions
//     and two buzzes on the same machine.
//
// Hashing rather than using the key's hex directly keeps it out of a URL that lands in the worker
// registry and devtools. It is public material, so that is hygiene rather than a control.

import { toHex } from '../crypto/bytes';

const SCOPE_PREFIX = '/push/';

/**
 * The scope id for an account, from its X25519 public key.
 *
 * Sixteen hex characters of SHA-256 — 64 bits, against a handful of accounts on one device.
 */
export async function scopeIdFor(x25519Public: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(x25519Public));
  return toHex(new Uint8Array(digest)).slice(0, 16);
}

export function scopePathFor(id: string): string {
  return `${SCOPE_PREFIX}${id}/`;
}

/** The id a scope URL names, or null if it is not one of ours. */
export function scopeIdOf(scopeUrl: string): string | null {
  try {
    const { pathname } = new URL(scopeUrl);
    if (!pathname.startsWith(SCOPE_PREFIX)) return null;
    const id = pathname.slice(SCOPE_PREFIX.length).replace(/\/$/, '');
    return /^[0-9a-f]{16}$/.test(id) ? id : null;
  } catch {
    return null;
  }
}

/** Every per-account registration this browser holds, by id. */
export async function pushRegistrations(): Promise<Map<string, ServiceWorkerRegistration>> {
  const out = new Map<string, ServiceWorkerRegistration>();
  if (!('serviceWorker' in navigator)) return out;
  for (const reg of await navigator.serviceWorker.getRegistrations()) {
    const id = scopeIdOf(reg.scope);
    if (id) out.set(id, reg);
  }
  return out;
}

export async function registrationFor(id: string): Promise<ServiceWorkerRegistration | null> {
  return (await pushRegistrations()).get(id) ?? null;
}

// How long to wait for a freshly registered worker to reach `activated`. Deliberately not
// `navigator.serviceWorker.ready`, which resolves the registration matching the PAGE — that is the
// root shell worker, and it would resolve immediately while this one was still installing.
const ACTIVATION_TIMEOUT_MS = 10_000;

/**
 * Register (or reuse) this account's worker and return it once it can take a subscription.
 *
 * `update()` on an existing one because a scope no page ever visits is checked for a new script
 * rarely, and a bug in the push worker would otherwise pin for a long time.
 */
export async function ensureRegistration(id: string, workerUrl: string): Promise<ServiceWorkerRegistration> {
  justRegistered.add(id);
  const existing = await registrationFor(id);
  if (existing) {
    void existing.update().catch(() => { /* offline, or the script is unchanged */ });
    if (existing.active) return existing;
    return waitForActive(existing);
  }
  const reg = await navigator.serviceWorker.register(workerUrl, { scope: scopePathFor(id) });
  return reg.active ? reg : waitForActive(reg);
}

function waitForActive(reg: ServiceWorkerRegistration): Promise<ServiceWorkerRegistration> {
  return new Promise((resolve, reject) => {
    const worker = reg.installing ?? reg.waiting ?? reg.active;
    if (!worker) return reject(new Error('the notification worker did not install'));
    if (worker.state === 'activated') return resolve(reg);
    const timer = setTimeout(() => {
      worker.removeEventListener('statechange', onChange);
      reject(new Error('the notification worker did not finish starting up'));
    }, ACTIVATION_TIMEOUT_MS);
    function onChange() {
      if (worker!.state === 'activated') {
        clearTimeout(timer);
        worker!.removeEventListener('statechange', onChange);
        resolve(reg);
      } else if (worker!.state === 'redundant') {
        clearTimeout(timer);
        worker!.removeEventListener('statechange', onChange);
        reject(new Error('the notification worker was discarded'));
      }
    }
    worker.addEventListener('statechange', onChange);
  });
}

/**
 * Turn this account's notifications off at the browser: drop the subscription, then the
 * registration.
 *
 * Needs no keys, which is what lets "remove from this device" do it from the locked screen. The
 * relay row it leaves behind cannot outlive it either way: the endpoint is dead, so the next
 * wake-up sent to it is refused and the row is deleted at that end.
 */
export async function tearDownScope(id: string): Promise<void> {
  justRegistered.delete(id);
  const reg = await registrationFor(id);
  if (!reg) return;
  try {
    const sub = await reg.pushManager.getSubscription();
    if (sub) await sub.unsubscribe();
  } catch {
    // Unregistering below still stops this browser being woken.
  }
  try {
    await reg.unregister();
  } catch { /* nothing more to try */ }
}

/**
 * Collect registrations that can no longer notify anyone.
 *
 * Deliberately NOT "every scope with no account signed in here". Signing out does not turn
 * notifications off — only the settings panel does — so a signed-out account's scope is healthy and
 * must be left alone, and in the installed app an account that lives only in the browser tab looks
 * exactly the same. The one safely collectable registration is one whose subscription is already
 * gone: there is nothing left to turn off and nothing to lose.
 */
export async function collectDeadScopes(): Promise<void> {
  for (const [id, reg] of await pushRegistrations()) {
    // One created in this page's lifetime is mid-setup: it exists before its subscription does, and
    // sweeping it there would break the very act that made it.
    if (justRegistered.has(id)) continue;
    try {
      if (await reg.pushManager.getSubscription()) continue;
      await reg.unregister();
    } catch { /* leave it; it will be reconsidered next open */ }
  }
}

// Registrations this page created, which the sweep must leave alone. Page-lifetime only: on the
// next load either a subscription exists or the registration really is dead.
const justRegistered = new Set<string>();
