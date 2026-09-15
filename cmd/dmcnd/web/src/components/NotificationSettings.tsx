// Turning new-mail notifications on for this device.
//
// What a notification can say is fixed and worth stating on the screen rather than in a doc: the
// relay that sends it cannot read the mail, so it says only that mail arrived. That is a property
// of how it is built, not a setting anyone could change later.

import { useCallback, useEffect, useState } from 'react';
import { deployment } from '@deployment';
import { Button } from '../ds';
import { SettingsSection } from './SettingsSection';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import {
  currentSubscription, forgetEndpoint, pushConfigured, pushNeedsInstall, pushSupported,
  rememberEndpoint, subscribeThisBrowser,
} from '../lib/push/subscription';

type State = 'loading' | 'off' | 'on' | 'unsupported' | 'needs-install' | 'blocked';

export function NotificationSettings({ address, keys }: { address: string; keys: WorkingKeys }) {
  const [state, setState] = useState<State>('loading');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const refresh = useCallback(async () => {
    if (pushNeedsInstall()) return setState('needs-install');
    if (!pushSupported()) return setState('unsupported');
    if (typeof Notification !== 'undefined' && Notification.permission === 'denied') return setState('blocked');
    setState((await currentSubscription()) ? 'on' : 'off');
  }, []);

  useEffect(() => { void refresh(); }, [address, refresh]);

  async function enable() {
    setBusy(true);
    setErr('');
    try {
      const sub = await subscribeThisBrowser();
      await deployment.push!.register(address, sub.endpoint, keys);
      rememberEndpoint(address, sub.endpoint);
      setState('on');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not turn notifications on.');
      void refresh();
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    setBusy(true);
    setErr('');
    try {
      const sub = await currentSubscription();
      if (sub) {
        // Withdraw this mailbox first, while the session and keys are still here. Only then drop
        // the browser's subscription — and only if no other account is using it, which
        // unsubscribing at the browser cannot know. Erring toward keeping it means at worst a
        // wake-up that says "New mail" for an account this browser no longer notifies.
        await deployment.push!.unregister(address, sub.endpoint, keys);
      }
      forgetEndpoint(address);
      setState('off');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not turn notifications off.');
    } finally {
      setBusy(false);
    }
  }

  if (!pushConfigured() || !deployment.push) return null;

  return (
    <SettingsSection title="Notifications">
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
        Be told when mail arrives, even with the app closed. A notification says only that mail
        arrived — never who wrote or what about, because the relay that sends it cannot read your
        mail. Opening it unlocks as usual.
      </div>

      {state === 'needs-install' && (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
          Add DMCN Mail to your Home Screen to turn notifications on. On iPhone and iPad they are
          only available to the installed app.
        </div>
      )}
      {state === 'unsupported' && (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
          This browser cannot receive notifications.
        </div>
      )}
      {state === 'blocked' && (
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
          Notifications are blocked for this site. Allow them in your browser settings, then come
          back.
        </div>
      )}

      {(state === 'on' || state === 'off') && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <Button onClick={() => void (state === 'on' ? disable() : enable())} disabled={busy}
            variant={state === 'on' ? 'secondary' : 'primary'}>
            {busy ? 'Working…' : state === 'on' ? 'Turn off on this device' : 'Turn on for this device'}
          </Button>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {state === 'on' ? 'On for this device.' : 'Off for this device.'}
          </span>
        </div>
      )}

      {state === 'on' && (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
          Notifications are per browser, not per account. If someone else signs in here too, a
          notification may be for their mail — it names neither of you either way.
        </div>
      )}

      {err && <div role="alert" style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{err}</div>}
    </SettingsSection>
  );
}
