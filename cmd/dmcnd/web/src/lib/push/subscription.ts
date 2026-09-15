// The browser half of new-mail notifications: asking permission, subscribing, and keeping the
// stored endpoint in step with the live one.
//
// Everything here is keyed on an ACCOUNT, not on the browser. A browser gives one push subscription
// per service worker registration, so each account gets a registration of its own under its own
// scope (see push/scopes.ts) and therefore an endpoint of its own. That is what lets a wake-up be
// attributed to a mailbox instead of to a device with several signed in.
//
// Deployment-agnostic on purpose. WHERE an endpoint gets registered differs — the product hands it
// to a mailbox relay over a signed mailbox op, a single-binary self-host stores it in the same
// process — so that one step goes through deployment.push and everything here is shared.
//
// Nothing in this file touches key material. A contentless push needs none, which is what keeps the
// lock model untouched by the feature.

import { PUSH_VAPID_PUBLIC_KEY } from '../config';
import { ensureRegistration, registrationFor } from './scopes';

/** Where the endpoint we last registered is remembered, per account. */
function storedKey(address: string): string {
  return `dmcn_push_endpoint:${address.toLowerCase()}`;
}

/** The push workers' shared cache. Origin-scoped, so every entry in it is named per account. */
export const PUSH_CACHE = 'dmcn-push-v1';

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
 * The subscription this account already holds, if any.
 *
 * Reads the account's own registration rather than `navigator.serviceWorker.ready`, which resolves
 * the registration controlling the PAGE — that is the shell worker, which holds no subscription and
 * would answer "off" for every account.
 */
export async function currentSubscription(id: string): Promise<PushSubscription | null> {
  if (!pushSupported()) return null;
  const reg = await registrationFor(id);
  if (!reg) return null;
  try {
    return await reg.pushManager.getSubscription();
  } catch {
    return null;
  }
}

/**
 * Subscribe this account, asking permission first.
 *
 * Must be called from a click: Safari requires a user gesture for the permission prompt, and every
 * browser penalises a site that asks on load.
 */
export async function subscribeAccount(id: string, workerUrl: string): Promise<PushSubscription> {
  if (!pushConfigured()) throw new Error('This deployment does not offer notifications.');
  if (!pushSupported()) throw new Error('This browser cannot receive notifications.');

  const permission = await Notification.requestPermission();
  if (permission !== 'granted') {
    throw new Error(permission === 'denied'
      ? 'Notifications are blocked for this site. You can re-enable them in your browser settings.'
      : 'Notifications were not allowed.');
  }
  const reg = await ensureRegistration(id, workerUrl);
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
 * The endpoint this account's worker parked after the browser rotated a subscription.
 *
 * The worker cannot register it itself — that needs the account's signing key, which it never
 * touches — so it leaves it here and the next app open hands it over.
 */
export async function takeParkedEndpoint(id: string): Promise<string | null> {
  if (!('caches' in window)) return null;
  try {
    const cache = await caches.open(PUSH_CACHE);
    const key = `/__dmcn_pending_push_endpoint/${id}`;
    const res = await cache.match(key);
    if (!res) return null;
    const endpoint = (await res.text()).trim();
    await cache.delete(key);
    return endpoint || null;
  } catch {
    return null;
  }
}

/** Whether this account was woken since it was last looked at, and clearing that mark. */
export async function wasWoken(id: string): Promise<boolean> {
  if (!('caches' in window)) return false;
  try {
    return !!(await (await caches.open(PUSH_CACHE)).match(`/__dmcn_woken/${id}`));
  } catch {
    return false;
  }
}

export async function clearWoken(id: string): Promise<void> {
  if (!('caches' in window)) return;
  try {
    await (await caches.open(PUSH_CACHE)).delete(`/__dmcn_woken/${id}`);
  } catch { /* the dot outstays its welcome; nothing worse */ }
}
