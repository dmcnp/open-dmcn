import { useEffect, useRef, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { useAccountSwitch } from '../lib/hooks/useAccountSwitch';
import { isInstalledApp } from '../lib/appContext';
import { AccountMonogram } from '../components/AccountMonogram';
import { AuthShell } from '../components/AuthShell';
import { deployment } from '@deployment';
import { Button, IconButton, Input } from '../ds';
import { Icon } from '../components/Icon';
import { accountForScope } from '../lib/push/whichAccount';
import { takeIntent } from '../lib/push/intent';


const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;

// Login is the per-device account picker. The encrypted keystores live only in this
// context's own IndexedDB (a browser tab and an installed app keep separate stores —
// see lib/appContext.ts), one per identity, so several accounts (work, personal) coexist.
// Unlocking here is the same act as switching accounts from the header — both run
// useAccountSwitch, which owns the crypto and the session handover.
export function Login() {
  const [passphrase, setPassphrase] = useState('');
  const {
    accounts, busy, error, needsPassword, beginUnlock, cancelUnlock, switchTo, forget,
    deviceUnlock, needsDevicePassword, unlockAll,
  } = useAccountSwitch();
  const [devicePassphrase, setDevicePassphrase] = useState('');
  const location = useLocation();
  const reason = (location.state as { reason?: string } | null)?.reason;
  const expired = reason === 'expired';
  const locked = reason === 'locked';
  // The account was re-keyed somewhere else, so the key stored here no longer opens the session.
  // The keystore is kept anyway: the old key is what reads the mail that arrived before the
  // change, and this device gets it back by pairing.
  const rekeyed = reason === 'rekeyed';
  // Absent ⇒ this deployment has no pairing flow; offer no route into one.
  const pairing = deployment.pairing;
  // The account a tapped notification was for. This screen is where such a tap lands whenever the
  // account is locked, which for a closed app is most of the time — so say which one it was,
  // instead of showing an undifferentiated list and making the person guess.
  const [woke, setWoke] = useState('');
  const wokeRow = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const id = takeIntent();
    if (!id) return;
    void accountForScope(id).then(a => { if (a) setWoke(a.address); });
  }, []);

  // Bring it into view and put the keyboard on its Unlock. Deliberately no further than that: the
  // unlock itself has to be a real gesture, and a passkey prompt fired from here would be refused.
  useEffect(() => {
    if (!woke || !wokeRow.current) return;
    wokeRow.current.scrollIntoView({ block: 'nearest' });
    wokeRow.current.querySelector('button')?.focus();
  }, [woke, accounts]);

  if (accounts === null) return null; // loading IndexedDB

  if (accounts.length === 0) {
    return (
      <AuthShell
        title="Set up this device"
        subtitle={`There's no identity stored in ${isInstalledApp() ? 'this app' : 'this browser'} yet.`}
        footer={deployment.signUp.prompt}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
            Your keys never leave your devices, so there's nothing on the server to sign
            in with. Bring an existing identity onto {isInstalledApp() ? 'this app' : 'this browser'}:
          </p>
          {pairing && <Link to={pairing.path}><Button size="lg" fullWidth>Add this device (pairing)</Button></Link>}
          <Link to="/import"><Button size="lg" variant={pairing ? 'secondary' : 'primary'} fullWidth>Import a backup or keystore</Button></Link>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Choose an account"
      subtitle="Unlock an identity stored on this device."
      footer={
        <span>
          Add another: {deployment.signUp.inline}
          {' · '}<Link to="/import" style={linkStyle}>import</Link>
          {pairing && <>{' · '}<Link to={pairing.path} style={linkStyle}>pair a device</Link></>}
        </span>
      }
    >
      {(expired || locked || rekeyed) && (
        <div style={{ marginBottom: 'var(--space-3)', padding: 'var(--space-3)', background: rekeyed ? 'var(--warning-subtle)' : 'var(--surface-sunken)', color: 'var(--text-muted)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>
          {rekeyed
            ? 'This account got a new key on another device, so this one can no longer sign in to it. '
              + 'Pair this device again to catch up. Nothing here was deleted — the key stored on this '
              + 'device still opens the mail that arrived before the change.'
            : expired
              ? 'Your session expired. Unlock again to continue.'
              : 'Locked while you were away. Unlock to continue.'}
        </div>
      )}
      {error && <div style={{ marginBottom: 'var(--space-3)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{error}</div>}

      {/* One unlock for every attached account, offered above the list because it is the shorter
          road when it applies: three accounts behind one passkey rather than three prompts. The
          list stays exactly as it was for anything not attached.

          Only from TWO accounts up. With one, this said the same thing as the row below it and
          offered a second primary button to reach the same mailbox by a different secret — the
          saving it exists for does not exist yet, so neither should the card. Settings is where an
          account learns it is attached, and says there that the shared unlock starts paying off at
          the second one. */}
      {deviceUnlock && deviceUnlock.addresses.length > 1 && (
        <form
          onSubmit={e => { e.preventDefault(); void unlockAll({ password: devicePassphrase, prefer: woke || undefined }); }}
          style={{ marginBottom: 'var(--space-3)', padding: 'var(--space-3)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', background: 'var(--surface-card)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}
        >
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
            {`Unlock this ${isInstalledApp() ? 'app' : 'browser'} to open all ${deviceUnlock.addresses.length} attached accounts at once.`}
          </div>
          {needsDevicePassword && (
            <Input label="Device password" type="password" autoFocus
              value={devicePassphrase} onChange={e => setDevicePassphrase(e.target.value)} />
          )}
          <div>
            <Button type="submit" disabled={busy} leftIcon={<Icon name="key" size={14} />}>
              {busy ? 'Unlocking…' : 'Unlock this device'}
            </Button>
          </div>
        </form>
      )}

      <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', overflow: 'hidden', background: 'var(--surface-card)' }}>
        {accounts.map((account, i) => {
          const { address, ks, unlocked } = account;
          const expanded = needsPassword === address && ks?.authMethod !== 'passkey';
          const isWoke = woke === address;
          return (
            <div key={address} ref={isWoke ? wokeRow : undefined}
              style={{
                borderBottom: i < accounts.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                background: isWoke ? 'var(--surface-sunken)' : undefined,
              }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: '11px 14px' }}>
                <AccountMonogram address={address} />
                <div style={{ flex: '1 1 0', minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{address}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 3, fontSize: 12, color: unlocked ? 'var(--brand-text)' : 'var(--warning)' }}>
                    <Icon name={unlocked ? 'shield-check' : 'lock'} size={11} />
                    {unlocked ? 'Unlocked' : 'Locked'}
                    {/* No keystore: a temporary session, usable until this tab closes. */}
                    {!ks && ' · temporary'}
                    {isWoke && <span style={{ color: 'var(--brand-text)' }}>{' · new mail'}</span>}
                  </div>
                </div>
                {!expanded && (
                  unlocked
                    ? <Button size="sm" disabled={busy} onClick={() => void switchTo(account)}>Continue</Button>
                    : <Button size="sm" disabled={busy} leftIcon={<Icon name="key" size={14} />} onClick={() => { setPassphrase(''); beginUnlock(account); }}>Unlock</Button>
                )}
                <IconButton variant="ghost" size="sm" aria-label="Remove from this device" disabled={busy} onClick={() => void forget(account)}>
                  <Icon name="trash" size={16} />
                </IconButton>
              </div>
              {expanded && (
                <form onSubmit={e => { e.preventDefault(); void switchTo(account, { password: passphrase }); }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: '0 14px 14px 58px' }}>
                  <Input label="Password" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} autoFocus />
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <Button size="sm" type="submit" disabled={busy}>{busy ? 'Unlocking…' : 'Unlock'}</Button>
                    <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={cancelUnlock}>Cancel</Button>
                  </div>
                </form>
              )}
            </div>
          );
        })}
      </div>
    </AuthShell>
  );
}
