// Keeping a registered device registered.
//
// `pushsubscriptionchange` is the event browsers are supposed to fire when they rotate a
// subscription, and it is unreliable enough across browsers that nothing can depend on it. So the
// repair happens here instead, on every app open: compare the endpoint this browser currently holds
// against the one we last handed over, and re-register when they differ.
//
// The same pass silently fixes two other things that would otherwise need someone to notice them: a
// mailbox that moved to another relay and left its rows behind, and a fleet VAPID rotation, which
// invalidates every subscription at once until each device re-subscribes.
//
// It renders nothing.

import { useEffect } from 'react';
import { deployment } from '@deployment';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import {
  currentSubscription, pushConfigured, pushSupported, rememberEndpoint, rememberedEndpoint,
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
        const sub = await currentSubscription();
        // No subscription means notifications are off for this browser. Nothing to repair: turning
        // them on is a deliberate act with a permission prompt, never something done behind
        // someone's back on a page load.
        if (!sub || cancelled) return;
        const parked = await takeParkedEndpoint();
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

  // A push that arrives while a window is open should refresh the inbox rather than only buzzing.
  // The worker posts this instead of relying on the poll, which is paused while a tab is hidden.
  useEffect(() => {
    if (!onNewMail || !('serviceWorker' in navigator)) return;
    const onMessage = (e: MessageEvent) => {
      if ((e.data as { type?: string } | null)?.type === 'dmcn:new-mail') onNewMail();
    };
    navigator.serviceWorker.addEventListener('message', onMessage);
    return () => navigator.serviceWorker.removeEventListener('message', onMessage);
  }, [onNewMail]);

  return null;
}
