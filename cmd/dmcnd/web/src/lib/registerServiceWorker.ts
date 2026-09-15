// Turning the service worker on.
//
// It has shipped for a long time and was never registered by anything, so its offline shell has
// never actually run. Registering it is what makes the app installable as a PWA and is the
// precondition for background notifications, since a push is delivered to a worker rather than to
// a page.
//
// Two deliberate choices. Only in a BUILT bundle: under the Vite dev server the modules are
// unbundled and must never be served from a cache. Note this is deliberately not the backend's
// DMCN_*_DEV flag — a dev-mode backend still serves a real built bundle, and gating on that would
// have left the worker unregistered in the end-to-end fleet, which is exactly where it needs
// testing. And on `load`, so registration never competes with first paint.
export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator) || !import.meta.env.PROD) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {
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
