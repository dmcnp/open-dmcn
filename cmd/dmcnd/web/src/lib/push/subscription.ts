// The browser half of new-mail notifications: asking permission, subscribing, and keeping the
// stored endpoint in step with the live one.
//
// Deployment-agnostic on purpose. WHERE an endpoint gets registered differs — the product hands it
// to a mailbox relay over a signed mailbox op, a single-binary self-host stores it in the same
// process — so that one step goes through deployment.push and everything here is shared.
//
// Nothing in this file touches key material. A contentless push needs none, which is what keeps
// the per-tab lock model untouched by the feature.

import { PUSH_VAPID_PUBLIC_KEY } from '../config';

/** Where the endpoint we last registered is remembered, per account. */
function storedKey(address: string): string {
  return `dmcn_push_endpoint:${address.toLowerCase()}`;
}

/** Whether this browser can receive background notifications at all. */
export function pushSupported(): boolean {
  return typeof window !== 'undefined'
    && 'serviceWorker' in navigator
    && 'PushManager' in window
    && 'Notification' in window;
}

/**
 * Whether push is missing only because the app is not installed.
 *
 * iOS exposes PushManager exclusively to a PWA added to the Home Screen, so on an iPhone in an
 * ordinary Safari tab the toggle cannot work and telling someone to install the app is the only
 * useful thing to say. Distinguished from "this browser has no push at all" so the copy can differ.
 */
export function pushNeedsInstall(): boolean {
  if (pushSupported()) return false;
  const iOS = /iPad|iPhone|iPod/.test(navigator.userAgent)
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const standalone = window.matchMedia?.('(display-mode: standalone)').matches
    || (navigator as { standalone?: boolean }).standalone === true;
  return iOS && !standalone;
}

/** Whether this deployment offers notifications — it needs a fleet application server key. */
export function pushConfigured(): boolean {
  return PUSH_VAPID_PUBLIC_KEY !== '';
}

/**
 * base64url → bytes, the form pushManager.subscribe wants its application server key in.
 *
 * Returns an ArrayBuffer rather than a view: a Uint8Array over a SharedArrayBuffer-capable buffer
 * does not satisfy BufferSource in current lib.dom typings, and the buffer is what the call wants
 * anyway.
 */
export function decodeVapidKey(base64url: string): ArrayBuffer {
  const padded = base64url.replace(/-/g, '+').replace(/_/g, '/')
    + '='.repeat((4 - (base64url.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

/**
 * The subscription this browser already holds, if any.
 *
 * `navigator.serviceWorker.ready` never rejects — if registration failed, it simply waits for ever.
 * Awaiting it bare would leave the settings card stuck on "loading" with nothing to read, so it is
 * raced against a deadline and a browser with no worker is reported as having no subscription,
 * which is the truth.
 */
export async function currentSubscription(): Promise<PushSubscription | null> {
  if (!pushSupported()) return null;
  const reg = await Promise.race([
    navigator.serviceWorker.ready,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), READY_TIMEOUT_MS)),
  ]);
  if (!reg) return null;
  return reg.pushManager.getSubscription();
}

// Long enough for a worker to install on a slow first load, short enough that a browser which will
// never register one does not leave the card spinning.
const READY_TIMEOUT_MS = 10_000;

/**
 * Subscribe this browser, asking permission first.
 *
 * Must be called from a click: Safari requires a user gesture for the permission prompt, and every
 * browser penalises a site that asks on load.
 */
export async function subscribeThisBrowser(): Promise<PushSubscription> {
  if (!pushConfigured()) throw new Error('This deployment does not offer notifications.');
  if (!pushSupported()) throw new Error('This browser cannot receive notifications.');

  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    throw new Error(permission === 'denied'
      ? 'Notifications are blocked for this site. You can re-enable them in your browser settings.'
      : 'Notifications were not allowed.');
  }
  const reg = await Promise.race([
    navigator.serviceWorker.ready,
    new Promise<null>((resolve) => setTimeout(() => resolve(null), READY_TIMEOUT_MS)),
  ]);
  if (!reg) throw new Error('This browser has not finished setting up notifications. Reload and try again.');
  const existing = await reg.pushManager.getSubscription();
  if (existing) return existing;
  // userVisibleOnly is required by Chrome, and honest here: every push shows a notification.
  return reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: decodeVapidKey(PUSH_VAPID_PUBLIC_KEY),
  });
}

export function rememberEndpoint(address: string, endpoint: string): void {
  try {
    localStorage.setItem(storedKey(address), endpoint);
  } catch {
    // Without this the reconcile re-registers on every open. Harmless: registration is idempotent.
  }
}

export function forgetEndpoint(address: string): void {
  try {
    localStorage.removeItem(storedKey(address));
  } catch { /* nothing to clean up */ }
}

export function rememberedEndpoint(address: string): string | null {
  try {
    return localStorage.getItem(storedKey(address));
  } catch {
    return null;
  }
}

/**
 * The endpoint the service worker parked after the browser rotated a subscription.
 *
 * The worker cannot register it itself — that needs the account's signing key, which it never
 * touches — so it leaves it here and the next app open hands it over.
 */
export async function takeParkedEndpoint(): Promise<string | null> {
  if (!('caches' in window)) return null;
  try {
    const cache = await caches.open('dmcn-mail-v3');
    const res = await cache.match('/__dmcn_pending_push_endpoint');
    if (!res) return null;
    const endpoint = (await res.text()).trim();
    await cache.delete('/__dmcn_pending_push_endpoint');
    return endpoint || null;
  } catch {
    return null;
  }
}
