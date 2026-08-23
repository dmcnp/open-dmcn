import { useEffect, useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { loginWithKeys } from '../lib/api/client';
import { decryptKeys, decryptKeysWithKey } from '../lib/crypto/keystore';
import { unlockPasskeyPRF } from '../lib/crypto/passkey';
import { keyPairFromPayloadJSON } from '../lib/crypto/keys';
import { listLocalKeystores, clearLocalKeystore, type LocalKeystore } from '../lib/crypto/localKeystore';
import { loadWorkingKeys, clearWorkingKeys } from '../lib/crypto/workingKeys';
import { workingKeyRef } from '../lib/sessionLifetime';
import { AuthShell } from '../components/AuthShell';
import { Button, IconButton, Input } from '../ds';
import { Icon } from '../components/Icon';
import { REGISTRATION_CLOSED, SIGNUP_URL, PETITION_MODE } from '../lib/config';

// The "create an account" affordance. On the consumer front door it links the
// in-app register page; on a closed (business) instance it points at the public
// signup front door instead — or disappears when none is configured.
// CreateAccountLink points at whatever "get an account here" means for this deployment. On a
// live domain nothing is created on demand — you ask an admin — so the wording has to change with
// it, or the link promises something the page cannot do.
function CreateAccountLink({ label, petitionLabel }: { label: string; petitionLabel: string }) {
  if (!REGISTRATION_CLOSED) {
    return <Link to="/register" style={linkStyle}>{PETITION_MODE ? petitionLabel : label}</Link>;
  }
  if (!SIGNUP_URL) return null;
  return <a href={SIGNUP_URL} style={linkStyle}>{label}</a>;
}

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;

interface Account {
  ks: LocalKeystore;
  unlocked: boolean; // working handles already present at this tab's ref
}

function initialsOf(address: string): string {
  const local = address.split('@')[0] || address;
  return local.slice(0, 2).toUpperCase();
}

// Login is the per-device account picker. The encrypted keystores live only in this
// browser (IndexedDB), one per identity, so several accounts (work, personal) coexist.
// Each tab binds to whichever account it unlocks here — that's the isolation boundary.
export function Login() {
  const [accounts, setAccounts] = useState<Account[] | null>(null);
  const [unlockFor, setUnlockFor] = useState<string | null>(null); // address mid-unlock
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { setSession } = useAuth();
  const { setKeys } = useKeys();
  const navigate = useNavigate();
  const location = useLocation();
  const expired = (location.state as { reason?: string } | null)?.reason === 'expired';

  const isUnlocked = async (ks: LocalKeystore): Promise<boolean> => {
    const wk = await loadWorkingKeys(workingKeyRef(ks.address));
    return wk !== null && wk.address === ks.address;
  };

  const refresh = async () => {
    const list = await listLocalKeystores();
    const withState = await Promise.all(list.map(async ks => ({ ks, unlocked: await isUnlocked(ks) })));
    withState.sort((a, b) => a.ks.address.localeCompare(b.ks.address));
    setAccounts(withState);
  };

  useEffect(() => { void refresh(); }, []);

  const finish = async (address: string, signKey: CryptoKey) => {
    const token = await loginWithKeys(address, signKey);
    setSession(address, token);
    navigate('/inbox');
  };

  const continueAccount = async (ks: LocalKeystore) => {
    setBusy(true); setError('');
    try {
      const wk = await loadWorkingKeys(workingKeyRef(ks.address));
      if (!wk || wk.address !== ks.address) { setUnlockFor(ks.address); return; }
      await finish(ks.address, wk.ed25519Sign);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to continue');
    } finally { setBusy(false); }
  };

  const unlock = async (ks: LocalKeystore) => {
    setBusy(true); setError('');
    try {
      let keyBytes: Uint8Array;
      if (ks.authMethod === 'passkey') {
        if (!ks.credentialId || !ks.prfSalt) throw new Error('keystore is missing passkey metadata');
        const aesKey = await unlockPasskeyPRF(ks.credentialId, ks.prfSalt);
        keyBytes = await decryptKeysWithKey(ks.bundle, aesKey);
      } else {
        if (!passphrase) throw new Error('password required');
        keyBytes = await decryptKeys(ks.bundle, passphrase);
      }
      const kp = keyPairFromPayloadJSON(keyBytes);
      const wk = await setKeys(ks.address, kp);
      await finish(ks.address, wk.ed25519Sign);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unlock failed');
    } finally { setBusy(false); }
  };

  const onUnlockClick = (ks: LocalKeystore) => {
    setError(''); setPassphrase(''); setUnlockFor(ks.address);
    if (ks.authMethod === 'passkey') void unlock(ks);
  };

  const forget = async (ks: LocalKeystore) => {
    await clearWorkingKeys(workingKeyRef(ks.address));
    await clearWorkingKeys(`acct:${ks.address}`);
    await clearLocalKeystore(ks.address);
    if (unlockFor === ks.address) setUnlockFor(null);
    await refresh();
  };

  if (accounts === null) return null; // loading IndexedDB

  if (accounts.length === 0) {
    return (
      <AuthShell
        title="Set up this device"
        subtitle="There's no identity stored in this browser yet."
        footer={<>Don't have a mailbox here yet? <CreateAccountLink label="Create an account" petitionLabel="Ask for a mailbox" /></>}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
            Your keys never leave your devices, so there's nothing on the server to sign
            in with. Bring an existing identity onto this browser:
          </p>
          {/* No pairing link: device pairing is a product-client feature and open-dmcn omits it
              deliberately, so /pair routes nowhere. Importing a backup is the whole of onboarding
              an existing identity here. */}
          <Link to="/import"><Button size="lg" fullWidth>Import a backup or keystore</Button></Link>
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
          Add another: <CreateAccountLink label="create" petitionLabel="ask for a mailbox" />
          {' · '}<Link to="/import" style={linkStyle}>import</Link>
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
        {accounts.map(({ ks, unlocked }, i) => {
          const expanded = unlockFor === ks.address && ks.authMethod !== 'passkey';
          return (
            <div key={ks.address} style={{ borderBottom: i < accounts.length - 1 ? '1px solid var(--border-subtle)' : 'none' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: '11px 14px' }}>
                <div style={{ flex: 'none', width: 32, height: 32, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 12, fontWeight: 600, fontFamily: 'var(--font-mono)', borderRadius: 'var(--radius-sm)' }}>
                  {initialsOf(ks.address)}
                </div>
                <div style={{ flex: '1 1 0', minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ks.address}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 3, fontSize: 12, color: unlocked ? 'var(--brand-text)' : 'var(--warning)' }}>
                    <Icon name={unlocked ? 'shield-check' : 'lock'} size={11} />
                    {unlocked ? 'Unlocked' : 'Locked'}
                  </div>
                </div>
                {!expanded && (
                  unlocked
                    ? <Button size="sm" disabled={busy} onClick={() => void continueAccount(ks)}>Continue</Button>
                    : <Button size="sm" disabled={busy} leftIcon={<Icon name="key" size={14} />} onClick={() => onUnlockClick(ks)}>{ks.authMethod === 'passkey' ? 'Unlock' : 'Unlock'}</Button>
                )}
                <IconButton variant="ghost" size="sm" aria-label="Remove from this device" disabled={busy} onClick={() => void forget(ks)}>
                  <Icon name="trash" size={16} />
                </IconButton>
              </div>
              {expanded && (
                <form onSubmit={e => { e.preventDefault(); void unlock(ks); }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: '0 14px 14px 58px' }}>
                  <Input label="Password" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} autoFocus />
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <Button size="sm" type="submit" disabled={busy}>{busy ? 'Unlocking…' : 'Unlock'}</Button>
                    <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={() => setUnlockFor(null)}>Cancel</Button>
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
