import { useRef, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../../src/lib/hooks/useAuth';
import { useKeys } from '../../src/lib/hooks/useKeys';
import { importChallenge, importIdentity } from '../../src/lib/api/client';
import { encryptKeys, encryptKeysWithKey, type EncryptedBundle } from '../../src/lib/crypto/keystore';
import { makeLocalKeystore, saveLocalKeystore } from '../../src/lib/crypto/localKeystore';
import { readExport, EXPORT_FORMAT, type KeystoreExport } from '../../src/lib/crypto/exportFile';
import { isPasskeySupported, createPasskeyPRF } from '../../src/lib/crypto/passkey';
import { sign } from '../../src/lib/crypto/sign';
import { toBase64, fromBase64, keyPairToPayloadJSON, type IdentityKeyPair } from '../../src/lib/crypto/keys';
import { AuthShell } from '../../src/components/AuthShell';
import { ChoiceRow } from '../../src/components/ChoiceRow';
import { Button, IconButton, Input } from '../../src/ds';
import { Icon } from '../../src/components/Icon';

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;

const fieldLabelStyle = { fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', display: 'block', marginBottom: 'var(--space-2)' } as const;

// A native control styled to match the DS Input (file picker + identity select
// have no DS primitive, so they reuse the input chrome via this style).
const nativeControlStyle = {
  width: '100%', fontFamily: 'var(--font-sans)', fontSize: 'var(--text-md)', color: 'var(--text-strong)',
  background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)',
  padding: '8px var(--space-3)',
} as const;

export function Import() {
  const [file, setFile] = useState<File | null>(null);
  const [cliPass, setCliPass] = useState('');
  // True once the chosen file is detected as a passkey-wrapped backup, which needs no
  // passphrase (it unlocks with a WebAuthn assertion).
  const [passkeyFile, setPasskeyFile] = useState(false);
  const [identities, setIdentities] = useState<Record<string, IdentityKeyPair> | null>(null);
  // Passkey material recovered while unlocking a passkey-protected backup. When set, the
  // import re-wraps the local keystore under this SAME credential rather than enrolling
  // a new one — a new enrollment would mint a credential that evicts (overwrites) the
  // one this backup file references, and would cost a second WebAuthn prompt.
  const [sourcePasskey, setSourcePasskey] = useState<{ credentialId: string; prfSalt: string; aesKey: CryptoKey } | null>(null);
  const [address, setAddress] = useState('');
  const passkeyOk = isPasskeySupported();
  const [usePasskey, setUsePasskey] = useState(passkeyOk);
  const [webPass, setWebPass] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [dragging, setDragging] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { setSession } = useAuth();
  const { setKeys } = useKeys();
  const navigate = useNavigate();

  const fmtSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  };

  const removeFile = () => {
    setFile(null); setPasskeyFile(false); setSourcePasskey(null); setError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  // Detect a passkey-wrapped DMCN backup on selection so the passphrase field can be
  // skipped (it unlocks with a WebAuthn assertion instead).
  const onFileChange = async (f: File | null) => {
    setFile(f);
    setPasskeyFile(false);
    setError('');
    if (!f) return;
    try {
      const parsed = JSON.parse(await f.text());
      if (parsed?.format === EXPORT_FORMAT && parsed?.authMethod === 'passkey') setPasskeyFile(true);
    } catch { /* not a JSON export → needs a passphrase */ }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('choose your keystore file (keystore.enc)');
      return;
    }
    setLoading(true);
    setError('');
    setSourcePasskey(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());

      // The reference client imports a DMCN backup export (a JSON keystore export
      // produced by Settings → Export). The product's CLI-keystore (keystore.enc) import
      // path is a product/CLI bridge and is not carried here.
      let asExport: KeystoreExport | null = null;
      try {
        const parsed = JSON.parse(new TextDecoder().decode(bytes));
        if (parsed?.format === EXPORT_FORMAT) asExport = parsed as KeystoreExport;
      } catch { /* not a DMCN backup export */ }
      if (!asExport) {
        throw new Error('unsupported file — choose a DMCN backup export (.dmcn / .json)');
      }

      // Passkey-wrapped backups unlock via a WebAuthn assertion (no passphrase);
      // passphrase-wrapped backups use the entered passphrase.
      const res = await readExport(asExport, { password: cliPass });
      const kps: Record<string, IdentityKeyPair> = { [asExport.address]: res.kp };
      // Carry the backup's passkey so the import can re-wrap under it (see handleImport).
      if (res.passkey) setSourcePasskey(res.passkey);
      const addrs = Object.keys(kps);
      if (addrs.length === 0) {
        throw new Error('this file contains no identities');
      }
      setIdentities(kps);
      setAddress(addrs[0]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to unlock keystore');
    } finally {
      setLoading(false);
    }
  };

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!identities || !address) return;
    setLoading(true);
    setError('');
    try {
      const keys = identities[address];
      const payloadBytes = new TextEncoder().encode(keyPairToPayloadJSON(keys));

      // Lock the keys for the web: passkey (WebAuthn PRF) or password fallback.
      let bundle: EncryptedBundle;
      let authMethod: 'password' | 'passkey';
      let credentialId: string | undefined;
      let prfSalt: string | undefined;
      if (usePasskey) {
        // Reuse the backup's own passkey when we have it (passkey-protected source on
        // this device): re-wrapping under the same credential keeps the file importable
        // and skips a redundant enrollment + prompt. A passkey read only succeeds when
        // that credential is present here, so reuse is always valid on this path. Only a
        // password-sourced import (no existing passkey) enrolls a fresh one.
        const enr = sourcePasskey ?? await createPasskeyPRF(address);
        bundle = await encryptKeysWithKey(payloadBytes, enr.aesKey);
        authMethod = 'passkey';
        credentialId = enr.credentialId;
        prfSalt = enr.prfSalt;
      } else {
        if (!webPass) {
          throw new Error('set a web password');
        }
        bundle = await encryptKeys(payloadBytes, webPass);
        authMethod = 'password';
      }

      // Prove possession of the identity's private key against the directory.
      const challenge = await importChallenge(address);
      if (challenge.ed25519_pub !== toBase64(keys.ed25519Public)) {
        throw new Error(`this keystore does not match the identity registered for ${address}`);
      }
      const seed = keys.ed25519Private.slice(0, 32);
      const signature = await sign(seed, fromBase64(challenge.challenge_nonce));

      // Store the encrypted keystore locally (never sent to the server).
      await saveLocalKeystore(makeLocalKeystore({ address, kp: keys, bundle, authMethod, credentialId, prfSalt }));

      const { session_token } = await importIdentity({
        address,
        challenge_nonce: challenge.challenge_nonce,
        challenge_signature: toBase64(signature),
      });

      await setKeys(address, keys);
      setSession(address, session_token);
      navigate('/inbox');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'import failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthShell
      title="Import an identity"
      subtitle="Bring a CLI keystore or backup file into this browser."
      footer={<><Link to="/login" style={linkStyle}>Back to sign in</Link></>}
    >
      <p style={{ margin: '0 0 var(--space-4)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
        Your keys are decrypted locally from a <code style={{ fontFamily: 'var(--font-mono)' }}>keystore.enc</code> or a DMCN
        backup file and never sent unencrypted.
      </p>

      {!identities ? (
        <form onSubmit={handleUnlock} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <input ref={fileInputRef} type="file" accept=".enc,.dmcn,.json" onChange={e => void onFileChange(e.target.files?.[0] ?? null)} style={{ display: 'none' }} />
          <div>
            <div style={fieldLabelStyle}>Keystore or backup file</div>
            {file ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', background: 'var(--surface-card)' }}>
                <div style={{ flex: 'none', width: 36, height: 36, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--brand-subtle)', color: 'var(--brand-text)', borderRadius: 'var(--radius-sm)' }}>
                  <Icon name="file" size={18} />
                </div>
                <div style={{ flex: '1 1 0', minWidth: 0 }}>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{file.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{fmtSize(file.size)}</div>
                </div>
                <IconButton variant="ghost" size="sm" aria-label="Remove file" onClick={removeFile}><Icon name="x" size={16} /></IconButton>
              </div>
            ) : (
              <div
                tabIndex={0} role="button"
                onClick={() => fileInputRef.current?.click()}
                onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInputRef.current?.click(); } }}
                onDragOver={e => { e.preventDefault(); if (!dragging) setDragging(true); }}
                onDragLeave={e => { e.preventDefault(); setDragging(false); }}
                onDrop={e => { e.preventDefault(); setDragging(false); void onFileChange(e.dataTransfer.files?.[0] ?? null); }}
                style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', gap: 10,
                  padding: '30px 20px', borderRadius: 'var(--radius-md)', cursor: 'pointer',
                  border: `1.5px dashed ${dragging ? 'var(--brand)' : 'var(--border-default)'}`,
                  background: dragging ? 'var(--brand-subtle)' : 'var(--surface-card)',
                  transition: 'border-color 120ms, background 120ms',
                }}
              >
                <Icon name="key" size={26} style={{ color: 'var(--text-subtle)' }} />
                <div style={{ fontSize: 14, color: 'var(--text-body)' }}><span style={{ color: 'var(--brand-text)', fontWeight: 600 }}>Browse</span> or drag a file here</div>
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-subtle)' }}>keystore.enc · .dmcn backup</div>
              </div>
            )}
          </div>

          {passkeyFile ? (
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
              This is a passkey-protected backup — you'll be prompted for your passkey to unlock it.
            </p>
          ) : (
            <div>
              <label htmlFor="ks-pass" style={fieldLabelStyle}>Keystore passphrase</label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input
                  id="ks-pass" type={showPass ? 'text' : 'password'} value={cliPass}
                  onChange={e => setCliPass(e.target.value)} placeholder="Enter your passphrase" autoComplete="off"
                  style={{ boxSizing: 'border-box', width: '100%', fontFamily: 'var(--font-sans)', fontSize: 15, color: 'var(--text-strong)', background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', height: 40, padding: '0 40px 0 12px' }}
                />
                <button type="button" aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'} onClick={() => setShowPass(s => !s)}
                  style={{ position: 'absolute', right: 6, width: 30, height: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'transparent', border: 'none', color: 'var(--text-subtle)', cursor: 'pointer', borderRadius: 'var(--radius-sm)' }}>
                  <Icon name={showPass ? 'eye-off' : 'eye'} size={16} />
                </button>
              </div>
            </div>
          )}
          {error && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
              <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
            </div>
          )}
          <Button type="submit" size="lg" fullWidth disabled={loading || !file} leftIcon={<Icon name="lock" size={16} />}>
            {loading ? 'Unlocking…' : passkeyFile ? 'Unlock with passkey' : 'Unlock'}
          </Button>
        </form>
      ) : (
        <form onSubmit={handleImport} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div>
            <label style={fieldLabelStyle}>Identity</label>
            <select value={address} onChange={e => setAddress(e.target.value)} style={nativeControlStyle}>
              {Object.keys(identities).map(a => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
          </div>

          <div>
            <label style={fieldLabelStyle}>Protect on this device</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              {passkeyOk && (
                <ChoiceRow checked={usePasskey} onClick={() => setUsePasskey(true)} title="Passkey" desc="Recommended — unlock with your device biometrics." />
              )}
              <ChoiceRow checked={!usePasskey} onClick={() => setUsePasskey(false)} title="Password" desc="Set a password to unlock on this browser." />
            </div>
            {!passkeyOk && <p style={{ color: 'var(--text-subtle)', fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)' }}>Passkeys aren't available in this browser.</p>}
          </div>

          {!usePasskey && (
            <Input
              label="Web password"
              type="password"
              value={webPass}
              onChange={e => setWebPass(e.target.value)}
            />
          )}

          {error && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
              <Icon name="alert-triangle" size={15} style={{ marginTop: 1 }} />
              <span>{error}</span>
            </div>
          )}
          <Button type="submit" size="lg" fullWidth disabled={loading}>
            {/* Only a password-sourced import actually enrolls a new passkey; a
                passkey backup reuses its own credential (sourcePasskey), so it's just "Import". */}
            {loading ? 'Importing…' : usePasskey && !sourcePasskey ? 'Import & create passkey' : 'Import'}
          </Button>
        </form>
      )}
    </AuthShell>
  );
}
