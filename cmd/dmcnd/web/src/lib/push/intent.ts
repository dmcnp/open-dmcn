// Where a tapped notification is meant to land.
//
// The worker cannot navigate an app window itself: WindowClient.navigate() rejects unless the
// window is controlled by the worker calling it, and app windows are controlled by the root shell
// worker rather than by a per-account notification worker. So the worker focuses a window and says
// which account it woke, or — when there is no window — opens one at a URL carrying the same thing.
// Both arrive here.
//
// The URL form has to be read BEFORE the router runs: the redirect that sends an unauthenticated
// visitor to /login drops the query string, so by the time a screen could ask, it is gone.

const PARAM = 'woke';
const KEY = 'dmcn_push_intent';

/**
 * The account id a URL carries, and the URL with it removed.
 *
 * Split out from the browser glue below so the decision can be tested without one. Returns a null
 * id for anything not shaped like one of ours: the parameter names which mailbox to open, so a
 * value that cannot be an id is somebody else's parameter and is left exactly where it was.
 */
export function parseIntentUrl(href: string): { id: string | null; url: string } {
  try {
    const url = new URL(href);
    const id = url.searchParams.get(PARAM);
    if (!id || !/^[0-9a-f]{16}$/.test(id)) return { id: null, url: href };
    url.searchParams.delete(PARAM);
    return { id, url: url.pathname + url.search + url.hash };
  } catch {
    return { id: null, url: href };
  }
}

/**
 * Take the woken account out of the current URL, if it is there, and park it.
 *
 * Called from main.tsx before the app renders. Rewrites the address bar so a reload does not
 * re-trigger the routing, and so the id is not left sitting in a shareable URL.
 */
export function captureIntentFromUrl(): void {
  try {
    const { id, url } = parseIntentUrl(window.location.href);
    if (!id) return;
    sessionStorage.setItem(KEY, id);
    window.history.replaceState(null, '', url);
  } catch { /* no sessionStorage: the tap just opens the app */ }
}

export function setIntent(id: string): void {
  try { sessionStorage.setItem(KEY, id); } catch { /* ignore */ }
}

/** Read the parked intent without consuming it. */
export function peekIntent(): string | null {
  try { return sessionStorage.getItem(KEY); } catch { return null; }
}

/** Read and clear the parked intent. Clearing on read is what stops it firing twice. */
export function takeIntent(): string | null {
  try {
    const id = sessionStorage.getItem(KEY);
    if (id) sessionStorage.removeItem(KEY);
    return id;
  } catch {
    return null;
  }
}
