// Turning new-mail notifications on for this account.
//
// What a notification can say is fixed and worth stating on the screen rather than in a doc: the
// relay that sends it cannot read the mail, so it says only that mail arrived. That is a property
// of how it is built, not a setting anyone could change later.
//
// Per ACCOUNT, not per browser. Each account holds its own push subscription under its own service
// worker scope, so turning this on here says nothing about any other account signed into the same
// browser, and turning it off leaves theirs alone.

import { useCallback, useEffect, useState } from 'react';
import { deployment } from '@deployment';
import { Button } from '../ds';
import { SettingsSection } from './SettingsSection';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { enableNotifications } from '../lib/push/enable';
import { rememberOfferAnswered } from '../lib/push/offer';
import { scopeIdFor, tearDownScope } from '../lib/push/scopes';
import {
  currentSubscription, forgetEndpoint, pushConfigured, pushNeedsInstall, pushSupported,
} from '../lib/push/subscription';

type State = 'loading' | 'off' | 'on' | 'unsupported' | 'needs-install' | 'blocked';

export function NotificationSettings({ address, keys }: { address: string; keys: WorkingKeys }) {
  const [state, setState] = useState<State>('loading');
  const [scopeId, setScopeId] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const refresh = useCallback(async () => {
    if (pushNeedsInstall()) return setState('needs-install');
    if (!pushSupported()) return setState('unsupported');
    if (typeof Notification !== 'undefined' && Notification.permission === 'denied') return setState('blocked');
    const id = await scopeIdFor(keys.x25519Public);
    setScopeId(id);
    setState((await currentSubscription(id)) ? 'on' : 'off');
  }, [keys]);

  useEffect(() => { void refresh(); }, [address, refresh]);

  async function enable() {
    setBusy(true);
    setErr('');
    try {
      const id = await enableNotifications(address, keys);
      setScopeId(id);
      // Someone who found this card has answered the question the inbox would otherwise put to
      // them (see push/offer.ts). Recorded here as well as there, so the offer never arrives after
      // a decision has already been made on this screen.
      rememberOfferAnswered(id);
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
      const sub = await currentSubscription(scopeId);
      // Withdraw at the relay first, while the keys are still here to sign it, and only then drop
      // the subscription. The reverse order would leave a row the relay keeps trying to wake.
      if (sub) await deployment.push!.unregister(address, sub.endpoint, keys);
      await tearDownScope(scopeId);
      forgetEndpoint(address);
      rememberOfferAnswered(scopeId);
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
        Get a notification when a new email arrives, even with the app closed. We can’t tell you
        who sent it or what’s in it, because we can’t see that. But we can tell you that a new
        email arrived and let you handle it from there.
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
            {state === 'on' ? 'On for this account, on this device.' : 'Off for this account.'}
          </span>
        </div>
      )}

      {state === 'on' && (
        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
          This is the only way to turn them off — signing out leaves them on, so mail arriving here
          still reaches you. Browsers occasionally reissue a notification subscription; repairing
          one is signed with your key, so it happens the next time you unlock this account.
        </div>
      )}

      {err && <div role="alert" style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{err}</div>}
    </SettingsSection>
  );
}
