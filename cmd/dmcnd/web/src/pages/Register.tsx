import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { register, ApiError } from '../lib/api/client';
import { toBase64 } from '../lib/crypto/keys';
import { isPasskeySupported } from '../lib/crypto/passkey';
import { enrollIdentity, persistAndSignIn } from '../lib/crypto/enrollment';
import { validateChosenAddress } from '../lib/address';
import { DEFAULT_DOMAIN } from '../lib/config';
import { AuthShell } from '../components/AuthShell';
import { ChoiceRow } from '../components/ChoiceRow';
import { Button, Input } from '../ds';
import { Icon } from '../components/Icon';

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;
const fieldLabelStyle = { fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', display: 'block', marginBottom: 'var(--space-2)' } as const;

// 0 none, 1 weak, 2 fair, 3 strong — small bucketed meter for the passphrase field.
function strengthOf(p: string): { pct: string; label: string; color: string } {
  if (p.length === 0) return { pct: '0%', label: '', color: 'var(--text-subtle)' };
  let s = 0;
  if (p.length >= 8) s++;
  if (p.length >= 14) s++;
  if (/[0-9]/.test(p) && /[a-z]/i.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  if (s <= 1) return { pct: '33%', label: 'Weak', color: 'var(--danger)' };
  if (s <= 2) return { pct: '66%', label: 'Fair', color: 'var(--warning)' };
  return { pct: '100%', label: 'Strong', color: 'var(--success)' };
}

// Register creates an account on THIS node's domain. The browser generates the keys and
// self-signs the IdentityRecord; the daemon (operator) attaches a routing credential and
// publishes it. Keys never leave the browser — the encrypted keystore is stored locally and
// the private key is only used to self-sign + log in. This is the reference client's
// single-domain self-service signup (no countersign/custody/billing surfaces).
export function Register() {
  const domain = DEFAULT_DOMAIN;
  const [localPart, setLocalPart] = useState('');
  const address = localPart.trim() ? `${localPart.trim()}@${domain}` : '';
  const passkeyOk = isPasskeySupported();
  const [method, setMethod] = useState<'passkey' | 'passphrase'>(passkeyOk ? 'passkey' : 'passphrase');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { setSession } = useAuth();
  const { setKeys } = useKeys();
  const navigate = useNavigate();

  const mismatch = confirmPassphrase.length > 0 && confirmPassphrase !== passphrase;
  const strength = strengthOf(passphrase);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const addrErr = validateChosenAddress(address);
    if (addrErr) { setError(addrErr); return; }
    if (method === 'passphrase') {
      if (passphrase.length < 8) { setError('Choose a passphrase of at least 8 characters'); return; }
      if (passphrase !== confirmPassphrase) { setError('Passphrases do not match'); return; }
    }
    setLoading(true);
    setError('');

    try {
      const enrolled = await enrollIdentity(
        address,
        method === 'passkey' ? { method: 'passkey' } : { method: 'passphrase', passphrase },
      );
      const { keys, identityRecordBytes, selfSignature } = enrolled;

      await register({
        address,
        ed25519_pub: toBase64(keys.ed25519Public),
        x25519_pub: toBase64(keys.x25519Public),
        identity_record: toBase64(identityRecordBytes),
        self_signature: toBase64(selfSignature),
      });

      const token = await persistAndSignIn(address, enrolled);
      await setKeys(address, keys);
      setSession(address, token);
      navigate('/inbox');
    } catch (err) {
      if (err instanceof ApiError && err.code === 'already_registered') {
        setError('That address is already taken — choose another, or sign in.');
      } else {
        setError(err instanceof Error ? err.message : 'registration failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      title="Create your account"
      subtitle={`Your end-to-end encrypted inbox on ${domain}`}
      footer={<>Already have an account? <Link to="/login" style={linkStyle}>Sign in</Link></>}
    >
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
        <div>
          <label htmlFor="local" style={fieldLabelStyle}>Choose your address</label>
          <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
            <input
              id="local" value={localPart} onChange={e => setLocalPart(e.target.value)}
              placeholder="you" autoComplete="off" autoCapitalize="none" spellCheck={false}
              style={{
                flex: 1, minWidth: 0, boxSizing: 'border-box', fontFamily: 'var(--font-sans)', fontSize: 15,
                color: 'var(--text-strong)', background: 'var(--surface-card)', border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-md) 0 0 var(--radius-md)', height: 40, padding: '0 12px',
              }}
            />
            <span style={{
              flex: 'none', height: 40, display: 'flex', alignItems: 'center', padding: '0 12px',
              fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-muted)',
              background: 'var(--surface-sunken)', border: '1px solid var(--border-default)', borderLeft: 'none',
              borderRadius: '0 var(--radius-md) var(--radius-md) 0',
            }}>@{domain}</span>
          </div>
        </div>

        <div>
          <div style={fieldLabelStyle}>How do you want to secure your account?</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {passkeyOk && (
              <ChoiceRow checked={method === 'passkey'} onClick={() => setMethod('passkey')} title="Passkey" desc="Recommended — unlock with your device biometrics." />
            )}
            <ChoiceRow checked={method === 'passphrase'} onClick={() => setMethod('passphrase')} title="Passphrase" desc="Encrypt your keys with a passphrase on this browser." />
          </div>
        </div>

        {method === 'passphrase' && (
          <>
            <div>
              <label htmlFor="pass" style={fieldLabelStyle}>Passphrase</label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input
                  id="pass" type={showPass ? 'text' : 'password'} value={passphrase}
                  onChange={e => setPassphrase(e.target.value)} placeholder="At least 8 characters" autoComplete="new-password"
                  style={{ boxSizing: 'border-box', width: '100%', fontFamily: 'var(--font-sans)', fontSize: 15, color: 'var(--text-strong)', background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', height: 40, padding: '0 40px 0 12px' }}
                />
                <button type="button" aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'} onClick={() => setShowPass(s => !s)}
                  style={{ position: 'absolute', right: 6, width: 30, height: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'transparent', border: 'none', color: 'var(--text-subtle)', cursor: 'pointer', borderRadius: 'var(--radius-sm)' }}>
                  <Icon name={showPass ? 'eye-off' : 'eye'} size={16} />
                </button>
              </div>
              {passphrase.length > 0 && (
                <div style={{ marginTop: 'var(--space-2)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <div style={{ flex: 1, height: 4, background: 'var(--surface-sunken)', borderRadius: 999 }}>
                    <div style={{ width: strength.pct, height: '100%', background: strength.color, borderRadius: 999, transition: 'width 150ms' }} />
                  </div>
                  <span style={{ fontSize: 'var(--text-xs)', color: strength.color }}>{strength.label}</span>
                </div>
              )}
            </div>
            <Input
              label="Confirm passphrase"
              type="password"
              value={confirmPassphrase}
              onChange={e => setConfirmPassphrase(e.target.value)}
              error={mismatch ? 'Passphrases do not match' : undefined}
            />
          </>
        )}

        {error && (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
            <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
          </div>
        )}

        <Button type="submit" size="lg" fullWidth disabled={loading || !localPart.trim()}>
          {loading ? 'Creating account…' : method === 'passkey' ? 'Create account with passkey' : 'Create account'}
        </Button>
      </form>

      <p style={{ margin: 'var(--space-4) 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', textAlign: 'center' }}>
        Have a backup file? <Link to="/import" style={linkStyle}>Import it</Link>
      </p>
    </AuthShell>
  );
}
