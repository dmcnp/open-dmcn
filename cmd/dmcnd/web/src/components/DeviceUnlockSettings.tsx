// Attaching this account to one unlock for the whole device.
//
// Every account here has its own passkey or password, which is why being signed into three of them
// means three unlocks. Attaching wraps this account's keys a second time under ONE secret shared
// by the accounts attached to it, so unlocking once opens all of them.
//
// The cost is stated at the moment of attaching rather than in a doc, because that is the moment
// it is accepted: one secret now opens every attached account on this device. The keys are no less
// protected at rest — the same encryption, the same passkey or password strength — but there is
// one door instead of several.
//
// Two secrets are needed, and both are asked for in ONE pass. The account's own, because proving
// the account is yours is what lets its keys be re-wrapped at all; and this device's, because that
// is the key they get wrapped under. Which fields appear is worked out in advance from how each is
// gated, so nobody is sent round the loop twice. Neither is stored.

import { useCallback, useEffect, useState } from 'react';
import { Button, Input } from '../ds';
import { SettingsSection } from './SettingsSection';
import { isPasskeySupported } from '../lib/crypto/passkey';
import { bundleKeyFor } from '../lib/crypto/reauth';
import { loadLocalKeystore } from '../lib/crypto/localKeystore';
import { attachAccount, attachedAddresses, detachAccount, loadDeviceKeystore } from '../lib/crypto/deviceKeystore';
import type { AuthMethod } from '../lib/crypto/localKeystore';

const muted = { fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' } as const;
const body = { fontSize: 'var(--text-sm)', color: 'var(--text-body)' } as const;

// Which secret the person is being asked to produce: none yet, one they already have, or a new one.
type Setup = null | { method: AuthMethod; creating: boolean };

export function DeviceUnlockSettings({ address }: { address: string }) {
  const [attached, setAttached] = useState<string[] | null>(null);
  const [deviceMethod, setDeviceMethod] = useState<AuthMethod | null>(null);
  const [accountMethod, setAccountMethod] = useState<AuthMethod | null>(null);
  const [setup, setSetup] = useState<Setup>(null);
  const [accountPassword, setAccountPassword] = useState('');
  const [devicePassword, setDevicePassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [done, setDone] = useState('');

  const refresh = useCallback(async () => {
    const ks = await loadDeviceKeystore();
    setDeviceMethod(ks?.authMethod ?? null);
    setAccountMethod((await loadLocalKeystore(address))?.authMethod ?? null);
    setAttached(await attachedAddresses());
  }, [address]);

  useEffect(() => { void refresh(); }, [address, refresh]);

  const isAttached = !!attached?.includes(address);
  const others = (attached ?? []).filter(a => a !== address);

  function reset() {
    setSetup(null);
    setAccountPassword('');
    setDevicePassword('');
  }

  // Begin, or complete, one attachment. `chosen` is present only when the device secret is being
  // created; afterwards the existing one is used and the method is already known.
  async function begin(chosen?: AuthMethod) {
    const method = chosen ?? deviceMethod;
    if (!method) return;
    const creating = !deviceMethod;
    // A password anywhere in the pair means a field to fill before anything can be attempted.
    const needsFields = accountMethod === 'password' || method === 'password';
    if (needsFields && !setup) {
      setErr('');
      setDone('');
      setSetup({ method, creating });
      return;
    }
    await commit(method, creating);
  }

  async function commit(method: AuthMethod, creating: boolean) {
    setBusy(true);
    setErr('');
    setDone('');
    try {
      // The account's own secret first — but only far enough to get the key that opens its
      // keystore, never the identity inside. That key is what gets re-wrapped; the private key
      // stays where it already was, encrypted once.
      const own = await loadLocalKeystore(address);
      if (!own) throw new Error('this account has no keystore on this device');
      const bundleKey = await bundleKeyFor(own, { password: accountPassword || undefined });
      await attachAccount({
        address,
        bundleKey,
        create: creating ? { authMethod: method, password: devicePassword || undefined } : undefined,
        password: devicePassword || undefined,
      });
      reset();
      setDone(creating
        ? 'Done. This device now has one unlock, and this account is on it.'
        : 'Done. One unlock now opens this account too.');
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not attach this account.');
    } finally {
      setBusy(false);
    }
  }

  async function detach() {
    setBusy(true);
    setErr('');
    setDone('');
    try {
      await detachAccount(address);
      reset();
      setDone('Detached. This account unlocks on its own again.');
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Could not detach this account.');
    } finally {
      setBusy(false);
    }
  }

  if (attached === null) return null; // still reading

  return (
    <SettingsSection title="One unlock for this device">
      <div style={muted}>
        Each account here has its own passkey or password, so each is unlocked separately. Attach an
        account and one unlock opens every attached account at once.
      </div>

      {isAttached ? (
        <>
          <div style={body}>
            This account is attached{deviceMethod === 'passkey' ? ' to a passkey' : ' to a device password'}.
            {others.length > 0
              ? ` Unlocking it also opens ${others.join(', ')}.`
              : ' It is the only account attached so far, so nothing has changed on the unlock'
                + ' screen yet — the shared unlock appears there once a second account joins it.'}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <Button variant="secondary" disabled={busy} onClick={() => void detach()}>
              {busy ? 'Working…' : 'Detach this account'}
            </Button>
            <span style={muted}>Its own passkey or password never stopped working, and stays as it is.</span>
          </div>
        </>
      ) : (
        <>
          <div style={body}>
            {deviceMethod
              ? `This device already has one unlock${others.length ? ` for ${others.join(', ')}` : ''}. Attaching puts this account behind the same secret.`
              : 'Nothing is attached yet. Attaching this account sets up the shared unlock.'}
          </div>
          {/* Said before it is accepted, not after. */}
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--warning)', lineHeight: 'var(--leading-normal)' }}>
            One secret will open every attached account on this device, where today each opens one.
            Nothing is stored less safely — there is simply one door instead of several.
          </div>

          {setup ? (
            <form
              onSubmit={e => { e.preventDefault(); void commit(setup.method, setup.creating); }}
              style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}
            >
              {accountMethod === 'password' && (
                <Input label={`Password for ${address}`} type="password" autoFocus
                  value={accountPassword} onChange={e => setAccountPassword(e.target.value)} />
              )}
              {setup.method === 'password' && (
                <Input
                  label={setup.creating ? 'Choose a password for this device' : 'Device password'}
                  type="password" autoFocus={accountMethod !== 'password'}
                  value={devicePassword} onChange={e => setDevicePassword(e.target.value)} />
              )}
              <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                <Button type="submit" disabled={busy}>{busy ? 'Working…' : 'Attach this account'}</Button>
                <Button type="button" variant="secondary" disabled={busy} onClick={reset}>Cancel</Button>
              </div>
            </form>
          ) : (
            <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              {deviceMethod ? (
                <Button disabled={busy} onClick={() => void begin()}>
                  {busy ? 'Working…' : 'Attach this account'}
                </Button>
              ) : (
                <>
                  {isPasskeySupported() && (
                    <Button disabled={busy} onClick={() => void begin('passkey')}>
                      {busy ? 'Working…' : 'Set up with a passkey'}
                    </Button>
                  )}
                  <Button variant="secondary" disabled={busy} onClick={() => void begin('password')}>
                    Set up with a password
                  </Button>
                </>
              )}
            </div>
          )}
        </>
      )}

      {err && <div role="alert" style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{err}</div>}
      {done && <div style={{ fontSize: 'var(--text-sm)', color: 'var(--brand-text)' }}>{done}</div>}
    </SettingsSection>
  );
}
