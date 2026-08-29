import { useCallback, useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import {
  createPetition, petitionStatus, completePetition, loginWithKeys, ApiError,
} from '../lib/api/client';
import { buildSelfSignedRecord } from '../lib/crypto/enrollment';
import { generateIdentityKeyPair, importEd25519PrivateKey, keyPairFromPayloadJSON, toBase64 } from '../lib/crypto/keys';
import { encryptKeys, encryptKeysWithKey, decryptKeys, decryptKeysWithKey, type EncryptedBundle } from '../lib/crypto/keystore';
import { makeLocalKeystore, saveLocalKeystore, loadLocalKeystore, clearLocalKeystore } from '../lib/crypto/localKeystore';
import { isPasskeySupported, createPasskeyPRF } from '../lib/crypto/passkey';
import { sign } from '../lib/crypto/sign';
import { unlockPasskeyPRF } from '../lib/crypto/passkey';
import { DEFAULT_DOMAIN } from '../lib/config';
import { AuthShell } from '../components/AuthShell';
import { ChoiceRow } from '../components/ChoiceRow';
import { Button, Input } from '../ds';
import { Icon } from '../components/Icon';

// Petition is the sign-up page for a domain whose root key is kept offline. Nobody — including
// this daemon — can mint an address there, so there is nothing to "create". What the page does
// instead is generate a keypair, prove possession of it, and hand back a code the person reads to
// their admin. The admin assigns an address; this page picks it up on its own.
//
// Two things follow from the design and shape this UI:
//
//   - There is no address field. The petitioner does not choose, which is precisely why an
//     unclaimed petition can be ignored: there is nothing in it worth taking.
//   - The wait is a human one — a message to an admin, maybe overnight. So the keys are encrypted
//     and stored under the code before the wait begins, and the page resumes from that on a later
//     visit. Losing the tab must not lose the keys the address is about to be bound to.

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;
const fieldLabelStyle = { fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', display: 'block', marginBottom: 'var(--space-2)' } as const;

// petitionCtx domain-separates the possession proof. Must match internal/petition sigContext.
const PETITION_CTX = new TextEncoder().encode('dmcn-petition-v1\0');

// PENDING_KEY names the localStorage slot holding the in-flight petition. Device-local and not
// secret: it is the code plus where to find the keys, both useless without the keystore itself.
const PENDING_KEY = 'dmcn-pending-petition';

interface PendingPetition {
  code: string;
  expiresAt: string;
  keystoreId: string; // provisional keystore address, re-keyed to the real one on completion
}

// provisionalId keys the encrypted keystore before an address exists. The '@' shape keeps it from
// ever colliding with a real address on this domain.
const provisionalId = (code: string) => `petition:${code}`;

function readPending(): PendingPetition | null {
  try {
    const raw = localStorage.getItem(PENDING_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw) as PendingPetition;
    if (!p.code || !p.keystoreId) return null;
    if (p.expiresAt && new Date(p.expiresAt).getTime() < Date.now()) return null;
    return p;
  } catch {
    return null;
  }
}

async function clearPending(p: PendingPetition | null) {
  localStorage.removeItem(PENDING_KEY);
  if (p) await clearLocalKeystore(p.keystoreId).catch(() => {});
}

export function Petition() {
  const domain = DEFAULT_DOMAIN;
  const passkeyOk = isPasskeySupported();
  const [method, setMethod] = useState<'passkey' | 'passphrase'>(passkeyOk ? 'passkey' : 'passphrase');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [pending, setPending] = useState<PendingPetition | null>(() => readPending());
  const [loading, setLoading] = useState(false);
  const [claiming, setClaiming] = useState(false);
  const [assigned, setAssigned] = useState('');
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const { setSession } = useAuth();
  const { setKeys } = useKeys();
  const navigate = useNavigate();
  const mismatch = confirmPassphrase.length > 0 && confirmPassphrase !== passphrase;

  // --- step 1: file the petition -----------------------------------------------------------
  const handleRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (method === 'passphrase') {
      if (passphrase.length < 8) { setError('Choose a passphrase of at least 8 characters'); return; }
      if (passphrase !== confirmPassphrase) { setError('Passphrases do not match'); return; }
    }
    setLoading(true);
    setError('');
    try {
      // Enrol the passkey first, inside the form's user activation, before key generation.
      const enr = method === 'passkey' ? await createPasskeyPRF(`petition@${domain}`) : null;

      const keys = await generateIdentityKeyPair();
      const seed = keys.ed25519Private.slice(0, 32);

      // Prove possession of BOTH keys. The X25519 half is in the signed bytes because mail is
      // sealed to it — an unproven encryption key would decide who can read the mailbox.
      const proofBytes = new Uint8Array(PETITION_CTX.length + keys.ed25519Public.length + keys.x25519Public.length);
      proofBytes.set(PETITION_CTX, 0);
      proofBytes.set(keys.ed25519Public, PETITION_CTX.length);
      proofBytes.set(keys.x25519Public, PETITION_CTX.length + keys.ed25519Public.length);
      const proof = await sign(seed, proofBytes);

      const { code, expires_at } = await createPetition({
        ed25519_pub: toBase64(keys.ed25519Public),
        x25519_pub: toBase64(keys.x25519Public),
        proof: toBase64(proof),
      });

      // Park the keys, encrypted, under the code. The admin conversation can take hours; this
      // page must survive being closed in the middle of it.
      const keyData = new TextEncoder().encode(JSON.stringify({
        ed25519_public: toBase64(keys.ed25519Public),
        ed25519_private: toBase64(keys.ed25519Private),
        x25519_public: toBase64(keys.x25519Public),
        x25519_private: toBase64(keys.x25519Private),
        device_id: toBase64(keys.deviceId),
        created_at: keys.createdAt,
      }));
      let bundle: EncryptedBundle;
      let authMethod: 'password' | 'passkey';
      let credentialId: string | undefined;
      let prfSalt: string | undefined;
      if (enr) {
        bundle = await encryptKeysWithKey(keyData, enr.aesKey);
        authMethod = 'passkey'; credentialId = enr.credentialId; prfSalt = enr.prfSalt;
      } else {
        bundle = await encryptKeys(keyData, passphrase);
        authMethod = 'password';
      }
      const id = provisionalId(code);
      await saveLocalKeystore(makeLocalKeystore({ address: id, kp: keys, bundle, authMethod, credentialId, prfSalt }));

      const p: PendingPetition = { code, expiresAt: expires_at, keystoreId: id };
      localStorage.setItem(PENDING_KEY, JSON.stringify(p));
      setPending(p);
      setPassphrase(''); setConfirmPassphrase('');
    } catch (err) {
      setError(err instanceof ApiError ? err.message : err instanceof Error ? err.message : 'could not request a mailbox');
    } finally {
      setLoading(false);
    }
  };

  // --- step 3: claim the assigned address --------------------------------------------------
  const claim = useCallback(async (p: PendingPetition, address: string) => {
    setClaiming(true);
    setError('');
    try {
      const ks = await loadLocalKeystore(p.keystoreId);
      if (!ks) throw new Error('the keys for this request are not on this device — request a new mailbox here, or finish on the device you started from');

      // Unlock in place, the same way Login does: the keys were encrypted with the passkey or
      // passphrase the account will go on using, so nothing new is asked of the person here.
      let keyBytes: Uint8Array;
      if (ks.authMethod === 'passkey') {
        if (!ks.credentialId || !ks.prfSalt) throw new Error('the stored keys are missing their passkey metadata');
        keyBytes = await decryptKeysWithKey(ks.bundle, await unlockPasskeyPRF(ks.credentialId, ks.prfSalt));
      } else {
        if (!passphrase) throw new Error('passphrase required');
        keyBytes = await decryptKeys(ks.bundle, passphrase);
      }
      const keys = keyPairFromPayloadJSON(keyBytes);
      const seed = keys.ed25519Private.slice(0, 32);

      const { identityRecordBytes } = await buildSelfSignedRecord(address, keys);

      await completePetition({ code: p.code, identity_record: toBase64(identityRecordBytes) });

      // Re-key the keystore from the provisional id to the real address, then drop the old entry.
      await saveLocalKeystore({ ...ks, address });
      await clearPending(p);
      setPending(null);

      const signKey = await importEd25519PrivateKey(seed);
      const token = await loginWithKeys(address, signKey);
      await setKeys(address, keys);
      setSession(address, token);
      navigate('/inbox');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'could not finish setting up your mailbox');
      setClaiming(false);
    }
  }, [method, passphrase, navigate, setKeys, setSession]);

  // --- step 2: wait ------------------------------------------------------------------------
  useEffect(() => {
    // Stop once assigned: there is nothing further to learn, and the claim is now waiting on the
    // person rather than on the admin.
    if (!pending || claiming || assigned) return;
    let stop = false;
    const tick = async () => {
      try {
        const s = await petitionStatus(pending.code);
        if (stop) return;
        if (s.status === 'assigned' && s.address) {
          // Show it and stop. Deliberately NOT claiming here: claiming unlocks the keystore, and
          // for a passkey that means a WebAuthn prompt. Firing one from a timer gives the person
          // an authentication dialog with no explanation of what approved or why — and browsers
          // increasingly require a user gesture for it, so on Safari it does not work at all.
          setAssigned(s.address);
        }
      } catch (err) {
        if (err instanceof ApiError && err.status === 404) {
          // Expired, or assigned and completed elsewhere. Either way this code is spent.
          await clearPending(pending);
          if (!stop) { setPending(null); setError('That request expired. You can ask for a new one.'); }
        }
      }
    };
    void tick();
    const id = setInterval(tick, 5000);
    return () => { stop = true; clearInterval(id); };
  }, [pending, claiming, assigned]);

  const copyCode = async () => {
    if (!pending) return;
    try {
      await navigator.clipboard.writeText(pending.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard unavailable — the code is on screen anyway */ }
  };

  // ------------------------------------------------------------------------- waiting screen
  if (pending) {
    // Assigned: the admin has acted, and the person needs to know that before anything asks them
    // to authenticate. One explicit action from here, which also gives the passkey prompt the user
    // gesture browsers want.
    if (assigned) {
      return (
        <AuthShell
          title="Your mailbox is ready"
          subtitle={`${assigned} was assigned to you`}
          footer={<>Not what you expected? <a href="#" style={linkStyle} onClick={async e => { e.preventDefault(); await clearPending(pending); setPending(null); setAssigned(''); }}>Cancel and start over</a></>}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
              padding: 'var(--space-4)', background: 'var(--surface-sunken)',
              border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)',
            }}>
              <Icon name="shield-check" size={20} style={{ flex: 'none', color: 'var(--success)' }} />
              <div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 16, color: 'var(--text-strong)' }}>{assigned}</div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Approved by your administrator</div>
              </div>
            </div>

            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
              {method === 'passkey'
                ? 'Unlock with your passkey to finish setting up and open your mailbox.'
                : 'Enter the passphrase you chose when you made this request, to unlock your keys and finish.'}
            </p>

            {method === 'passphrase' && (
              <Input label="Passphrase" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} />
            )}

            {error && (
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
                <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
              </div>
            )}

            <Button
              size="lg"
              fullWidth
              disabled={claiming || (method === 'passphrase' && !passphrase)}
              onClick={() => claim(pending, assigned)}
            >
              {claiming ? 'Setting up…' : 'Open my mailbox'}
            </Button>
          </div>
        </AuthShell>
      );
    }

    // Still waiting on the admin.
    return (
      <AuthShell
        title="Give this code to your administrator"
        subtitle={`They will use it to set up your mailbox on ${domain}`}
        footer={<>Changed your mind? <a href="#" style={linkStyle} onClick={async e => { e.preventDefault(); await clearPending(pending); setPending(null); }}>Cancel this request</a></>}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 28, letterSpacing: '0.06em', textAlign: 'center',
            color: 'var(--text-strong)', background: 'var(--surface-sunken)', border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-md)', padding: 'var(--space-4)', userSelect: 'all',
          }}>{pending.code}</div>

          <Button variant="secondary" fullWidth onClick={copyCode}>
            <Icon name={copied ? 'check' : 'copy'} size={15} style={{ marginRight: 6 }} />
            {copied ? 'Copied' : 'Copy code'}
          </Button>

          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
            Read this code to your administrator however you normally reach them. They pick your
            address — you do not choose it here, and nothing is created until they act.
          </p>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            This page checks every few seconds and will tell you as soon as it is approved. You can
            close it and come back on this device
            {pending.expiresAt ? ` — the request expires ${new Date(pending.expiresAt).toLocaleString()}` : ''}.
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--text-subtle)', fontSize: 'var(--text-sm)' }}>
            <Icon name="lock" size={14} style={{ flex: 'none' }} />
            <span>Your keys were made in this browser and stay here. Only the public half was sent.</span>
          </div>

          {error && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
              <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
            </div>
          )}
        </div>
      </AuthShell>
    );
  }

  // ------------------------------------------------------------------------- request screen
  return (
    <AuthShell
      title="Ask for a mailbox"
      subtitle={`${domain} is administered by a person, not a sign-up form`}
      footer={<>Already have an account? <Link to="/login" style={linkStyle}>Sign in</Link></>}
    >
      <form onSubmit={handleRequest} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
        <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
          Your keys are made here, in this browser, and never leave it. We will give you a short code
          to pass to whoever runs {domain}; they choose your address and set it up.
        </p>

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
            <Input label="Passphrase" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} />
            <Input
              label="Confirm passphrase" type="password" value={confirmPassphrase}
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

        <Button type="submit" size="lg" fullWidth disabled={loading}>
          {loading ? 'Requesting…' : 'Request a mailbox'}
        </Button>
      </form>

      <p style={{ margin: 'var(--space-4) 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', textAlign: 'center' }}>
        Have a backup file? <Link to="/import" style={linkStyle}>Import it</Link>
      </p>
    </AuthShell>
  );
}
