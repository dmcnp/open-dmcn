// Turning the service worker on.
//
// It has shipped for a long time and was never registered by anything, so its offline shell has
// never actually run. Registering it is what makes the app installable as a PWA and is the
// precondition for background notifications, since a push is delivered to a worker rather than to
// a page.
//
// This is the SHELL worker only. Notifications are delivered to a separate per-account worker
// registered on demand (see push/scopes.ts), which is why nothing here subscribes to anything.

import { collectDeadScopes } from './push/scopes';

// Two deliberate choices. Only in a BUILT bundle: under the Vite dev server the modules are
// unbundled and must never be served from a cache. Note this is deliberately not the backend's
// DMCN_*_DEV flag — a dev-mode backend still serves a real built bundle, and gating on that would
// have left the worker unregistered in the end-to-end fleet, which is exactly where it needs
// testing. And on `load`, so registration never competes with first paint.
export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator) || !import.meta.env.PROD) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(dropLegacyRootSubscription)
      // A per-account notification worker whose subscription the browser has already discarded can
      // never notify anyone again. Nothing else would ever remove it — signing out deliberately
      // does not — so this is the one sweep, and it only touches registrations with nothing left
      // to lose.
      .then(() => collectDeadScopes())
      .catch(() => {
        // A failed registration costs offline support and notifications, nothing else. The app must
        // still start.
      });
  });
  installStaleShellRecovery();
}

// The one failure a cached shell can cause, and how it gets out of it.
//
// The worker serves the shell network-first, so an online visitor always gets the current one. But
// a visitor who is OFFLINE, whose last visit predates a deploy, gets a cached shell referencing
// content-hashed chunks that no longer exist anywhere — and the app white-screens with a module
// that will not load.
//
// Shed the worker and reload once. The sessionStorage latch is what stops that becoming a reload
// loop when the real cause is something else entirely.
const RESET_LATCH = 'dmcn_sw_reset';

function installStaleShellRecovery(): void {
  window.addEventListener('error', (e) => {
    if (!(e.target instanceof HTMLScriptElement)) return;
    if (!navigator.serviceWorker.controller) return;
    try {
      if (sessionStorage.getItem(RESET_LATCH)) return;
      sessionStorage.setItem(RESET_LATCH, '1');
    } catch {
      return; // no sessionStorage (private mode): better to leave the page alone than loop
    }
    void navigator.serviceWorker.getRegistration()
      .then((r) => r?.unregister())
      .then(() => location.reload());
  }, true);
}

// Notifications used to be registered against the ROOT worker, one subscription for the whole
// browser. They are per account now, each under its own scope, and this worker no longer has a push
// handler at all — so a subscription left over from that era would be delivered here and show
// Chrome's own "this site was updated in the background" notice instead of anything we wrote.
//
// Dropping it locally is enough. The relay rows pointing at it cannot outlive it: the endpoint is
// dead, so the first wake-up sent to it is refused and the row is deleted at that end.
async function dropLegacyRootSubscription(reg: ServiceWorkerRegistration): Promise<void> {
  try {
    const sub = await reg.pushManager.getSubscription();
    if (sub) await sub.unsubscribe();
  } catch {
    // Not supported here, or already gone. Either way there is nothing to clean up.
  }
}
