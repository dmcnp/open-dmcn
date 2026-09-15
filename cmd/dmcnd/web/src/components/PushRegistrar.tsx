// Keeping a registered account registered, and answering the worker when it asks.
//
// `pushsubscriptionchange` is the event browsers are supposed to fire when they rotate a
// subscription, and it is unreliable enough across browsers that nothing can depend on it. So the
// repair happens here instead, on every app open: compare the endpoint this account's registration
// currently holds against the one we last handed over, and re-register when they differ.
//
// The same pass silently fixes two other things that would otherwise need someone to notice them: a
// mailbox that moved to another relay and left its rows behind, and a fleet VAPID rotation, which
// invalidates every subscription at once until each device re-subscribes.
//
// It renders nothing.

import { useEffect } from 'react';
import { deployment } from '@deployment';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { registrationFor, scopeIdFor } from '../lib/push/scopes';
import {
  clearWoken, pushConfigured, pushSupported, rememberEndpoint, rememberedEndpoint,
  takeParkedEndpoint,
} from '../lib/push/subscription';

export function PushRegistrar({ address, keys, onNewMail }: {
  address: string;
  keys: WorkingKeys;
  onNewMail?: () => void;
}) {
  // Re-register whenever the app opens or comes back to the foreground.
  useEffect(() => {
    if (!pushConfigured() || !deployment.push || !pushSupported() || !address) return;
    let cancelled = false;

    const reconcile = async () => {
      try {
        const id = await scopeIdFor(keys.x25519Public);
        // This account is looking at its mail, so whatever woke it has been seen.
        void clearWoken(id);
        const reg = await registrationFor(id);
        // No registration means notifications are off for this account. Nothing to repair: turning
        // them on is a deliberate act with a permission prompt, never something done behind
        // someone's back on a page load. Note this must NOT create one.
        if (!reg || cancelled) return;
        // A scope no page ever navigates to is checked for a new worker script rarely, so a fix to
        // push-sw.js would otherwise take a long time to reach a device.
        void reg.update().catch(() => { /* offline, or unchanged */ });
        const sub = await reg.pushManager.getSubscription();
        if (!sub || cancelled) return;
        const parked = await takeParkedEndpoint(id);
        const known = rememberedEndpoint(address);
        if (!parked && known === sub.endpoint) return;
        await deployment.push!.register(address, sub.endpoint, keys);
        if (!cancelled) rememberEndpoint(address, sub.endpoint);
      } catch {
        // Offline, or a relay is down. The next open tries again, and registration is idempotent.
      }
    };

    void reconcile();
    const onVisible = () => { if (document.visibilityState === 'visible') void reconcile(); };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [address, keys]);

  // A push that arrives while this account is on screen should refresh the inbox rather than
  // buzzing. The worker cannot see WHICH account a window is showing, so it asks, and only a reply
  // from the account it woke withdraws the notification — a window showing someone else's mail must
  // never swallow it.
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;
    let mine = '';
    void scopeIdFor(keys.x25519Public).then(id => { mine = id; });

    const onMessage = (e: MessageEvent) => {
      const data = e.data as { type?: string; scopeId?: string } | null;
      if (data?.type !== 'dmcn:new-mail') return;
      const forMe = !!mine && data.scopeId === mine && document.visibilityState === 'visible';
      e.ports[0]?.postMessage({ foreground: forMe });
      if (forMe) {
        void clearWoken(mine);
        onNewMail?.();
      }
    };
    navigator.serviceWorker.addEventListener('message', onMessage);
    return () => navigator.serviceWorker.removeEventListener('message', onMessage);
  }, [keys, onNewMail]);

  return null;
}
