import { useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { useAccountSwitch } from '../lib/hooks/useAccountSwitch';
import { isInstalledApp } from '../lib/appContext';
import { AccountMonogram } from '../components/AccountMonogram';
import { AuthShell } from '../components/AuthShell';
import { deployment } from '@deployment';
import { Button, IconButton, Input } from '../ds';
import { Icon } from '../components/Icon';


const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;

// Login is the per-device account picker. The encrypted keystores live only in this
// context's own IndexedDB (a browser tab and an installed app keep separate stores —
// see lib/appContext.ts), one per identity, so several accounts (work, personal) coexist.
// Unlocking here is the same act as switching accounts from the header — both run
// useAccountSwitch, which owns the crypto and the session handover.
export function Login() {
  const [passphrase, setPassphrase] = useState('');
  const { accounts, busy, error, needsPassword, beginUnlock, cancelUnlock, switchTo, forget } = useAccountSwitch();
  const location = useLocation();
  const expired = (location.state as { reason?: string } | null)?.reason === 'expired';

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
          <Link to="/pair"><Button size="lg" fullWidth>Add this device (pairing)</Button></Link>
          <Link to="/import"><Button size="lg" variant="secondary" fullWidth>Import a backup or keystore</Button></Link>
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
          {' · '}<Link to="/pair" style={linkStyle}>pair a device</Link>
        </span>
      }
    >
      {expired && (
        <div style={{ marginBottom: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--surface-sunken)', color: 'var(--text-muted)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>
          Your session expired. Unlock again to continue.
        </div>
      )}
      {error && <div style={{ marginBottom: 'var(--space-3)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{error}</div>}

      <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', overflow: 'hidden', background: 'var(--surface-card)' }}>
        {accounts.map((account, i) => {
          const { address, ks, unlocked } = account;
          const expanded = needsPassword === address && ks?.authMethod !== 'passkey';
          return (
            <div key={address} style={{ borderBottom: i < accounts.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: '11px 14px' }}>
                <AccountMonogram address={address} />
                <div style={{ flex: '1 1 0', minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{address}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 3, fontSize: 12, color: unlocked ? 'var(--brand-text)' : 'var(--warning)' }}>
                    <Icon name={unlocked ? 'shield-check' : 'lock'} size={11} />
                    {unlocked ? 'Unlocked' : 'Locked'}
                    {/* No keystore: a temporary session, usable until this tab closes. */}
                    {!ks && ' · temporary'}
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
