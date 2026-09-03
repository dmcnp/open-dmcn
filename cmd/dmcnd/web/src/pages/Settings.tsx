import { Children, Fragment, useEffect, useState } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { useIsMobile } from '../lib/useIsMobile';
import { logout as apiLogout, lookupIdentity } from '../lib/api/client';
import { toHex } from '../lib/crypto/keys';
import { unlockBackupBytes } from '../lib/crypto/reauth';
import { buildPasswordExport, buildPasskeyExport, triggerDownload, type ExportAuth } from '../lib/crypto/exportFile';
import { encryptKeys } from '../lib/crypto/keystore';
import { keyPairToPayloadJSON } from '../lib/crypto/keys';
import { isPasskeySupported, createPasskeyPRF } from '../lib/crypto/passkey';
import { makeLocalKeystore, saveLocalKeystore, loadLocalKeystore, type LocalKeystore } from '../lib/crypto/localKeystore';
import { isStoragePersisted, requestPersistentStorage } from '../lib/crypto/storage';
import { isStaySignedIn, setStaySignedIn } from '../lib/sessionLifetime';
import { readTheme, readThemePref, readDensity, writeThemePref, writeDensity, type ThemePref, type Density } from '../lib/theme';
import { APP_VERSION } from '../lib/config';
import { PageShell } from '../components/PageShell';
import { BlockedSenders } from '../components/BlockedSenders';
import type { MailOutletContext } from '../components/AppLayout';
import { useSettings } from '../lib/hooks/useSettings';
import { useStorageUsage } from '../lib/hooks/useStorageUsage';
import { Badge, Button, Input, Textarea, Switch, Tabs, UsageMeter } from '../ds';
import { useStorageMode } from '../lib/hooks/useStorageMode';
import { deployment } from '@deployment';
import { Icon } from '../components/Icon';
import { formatBytes } from '../lib/format';

type Section = 'profile' | 'privacy' | 'appearance' | 'account';

// StorageCard surfaces the owner's personal-storage usage (Sent, contacts,
// settings, flags) against their effective quota. An unbounded quota (0) shows the
// used amount without a bar. When the deploy has Stripe billing enabled it also offers
// an upgrade path (plans → Stripe Checkout → operator-signed quota grant).
function StorageCard() {
  const { usage, loading, refresh } = useStorageUsage();
  const { localOnly } = useStorageMode();
  const unbounded = usage != null && usage.quotaBytes === 0;
  const Upgrade = deployment.storageUpgrade;

  return (
    <section style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      {/* A deployment with no billing has no plan to speak of — dmcnd self-host is the whole
          product for its owner. Name the section for what it actually contains. */}
      <SectionHeading title={Upgrade ? 'Plan & storage' : 'Storage'} />
      <div style={{
        background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)',
        padding: 'var(--space-6)', display: 'flex', flexDirection: 'column', gap: 'var(--space-5)',
      }}>
        <span style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-strong)' }}>Personal storage</span>
        {localOnly ? (
          /* Where the state lives matters more than how much of it there is. A relay that
             hosts no personal storage is a valid deployment, but it means none of this
             follows the account to another device — and finding that out by opening a
             second device to an empty Sent folder reads as data loss. */
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-body)', lineHeight: 'var(--leading-normal)' }}>
            This server doesn't store your mailbox state, so your sent mail, contacts, settings and
            message flags are kept in <strong>this browser only</strong>. They won't appear on your
            other devices, and clearing this browser's data loses them.
          </p>
        ) : usage == null ? (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {loading ? 'Loading usage…' : 'Usage unavailable right now.'}
          </p>
        ) : unbounded ? (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-body)' }}>
            Using <strong>{formatBytes(usage.usedBytes)}</strong> — no storage limit on this account.
          </p>
        ) : (
          <UsageMeter
            value={usage.usedBytes}
            max={usage.quotaBytes}
            valueText={`${formatBytes(usage.usedBytes)} of ${formatBytes(usage.quotaBytes)}`}
          />
        )}
        {!localOnly && (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
            Covers your sent mail, contacts, settings and message flags — all end-to-end encrypted and
            stored only as ciphertext on your relay.
          </p>
        )}
        {/* Whether more storage can be bought, and how, belongs to whoever runs the service. */}
        {!localOnly && Upgrade && <Upgrade usage={usage} onChanged={refresh} />}
      </div>
    </section>
  );
}

// Uppercase section eyebrow, with optional right-aligned meta (a renewal date, a status).
function SectionHeading({ title, meta }: { title: string; meta?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 'var(--space-4)' }}>
      <h2 style={{ margin: 0, fontSize: 'var(--text-sm)', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{title}</h2>
      {meta && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-subtle)' }}>{meta}</span>}
    </div>
  );
}

// Groups related rows behind one border, hairline-separated. The divider is drawn BETWEEN
// rows rather than under each, so the last row never trails a border into the card edge —
// and a conditional row that renders null takes its divider with it.
function RowGroup({ children }: { children: React.ReactNode }) {
  const rows = Children.toArray(children).filter(Boolean);
  return (
    <div style={{
      background: 'var(--surface-card)', border: '1px solid var(--border-subtle)',
      borderRadius: 'var(--radius-md)', display: 'flex', flexDirection: 'column',
    }}>
      {rows.map((row, i) => (
        <Fragment key={i}>
          {i > 0 && <div style={{ height: 1, background: 'var(--border-subtle)' }} />}
          {row}
        </Fragment>
      ))}
    </div>
  );
}

// Settings row: title + description on the left, control on the right. `grouped` is the
// inside-a-RowGroup variant — inset padding, and no border of its own.
function Row({ title, desc, grouped, children }: { title: string; desc?: string; grouped?: boolean; children?: React.ReactNode }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 'var(--space-6)',
      padding: grouped ? 'var(--space-5) var(--space-6)' : 'var(--space-4) 0',
      borderBottom: grouped ? undefined : '1px solid var(--border-subtle)',
    }}>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>{title}</div>
        {desc && <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2 }}>{desc}</div>}
      </div>
      {children && <div style={{ flex: 'none' }}>{children}</div>}
    </div>
  );
}

// Connected segmented control (theme / density choices).
function SegOption({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick} style={{
      padding: '6px 14px', border: '1px solid var(--border-default)', marginLeft: -1, font: 'inherit', fontSize: 'var(--text-sm)',
      background: active ? 'var(--brand-subtle)' : 'var(--surface-card)', color: active ? 'var(--brand-text)' : 'var(--text-body)',
      fontWeight: active ? 600 : 500, cursor: 'pointer',
    }}>{children}</button>
  );
}

export function Settings() {
  const { address, clearSession } = useAuth();
  const { keys, clearKeys } = useKeys();
  const navigate = useNavigate();
  const embedded = !useIsMobile();
  // The shell hands down onAppearanceChange so toggling theme/density here re-themes
  // the whole desktop shell live. (Standalone/mobile uses its own PageShell preview.)
  const { onAppearanceChange } = useOutletContext<MailOutletContext>();

  const { settings, updateSettings } = useSettings();
  const [section, setSection] = useState<Section>('profile');
  // Profile form (synced account settings). Seeded from the loaded settings doc.
  const [signature, setSignature] = useState('');
  const [composePlainText, setComposePlainText] = useState(false);
  // Reading privacy (synced). Lives on the Privacy tab, which has no Save button, so it
  // writes on toggle — a privacy switch that silently needed a Save press elsewhere on the
  // page would be the worst possible way to get this one wrong.
  const [remoteImages, setRemoteImages] = useState(false);
  const [remoteImagesErr, setRemoteImagesErr] = useState('');
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileMsg, setProfileMsg] = useState('');
  const [fingerprint, setFingerprint] = useState('');

  // Backup & recovery. The encrypted keystore lives only in this browser, so we
  // offer a user-held export (passphrase- or passkey-protected) as the total-device-
  // loss safety net, plus a local password change. Both re-unlock via reauth.
  const [keystore, setKeystore] = useState<LocalKeystore | null>(null);
  const authMethod = keystore?.authMethod ?? null;
  const passkeyOk = isPasskeySupported();
  const [exportMode, setExportMode] = useState<ExportAuth>(passkeyOk ? 'passkey' : 'password');
  const [exportPw, setExportPw] = useState('');
  const [exportCurrentPw, setExportCurrentPw] = useState('');
  const [showExport, setShowExport] = useState(false);
  const [curPw, setCurPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [showChangePw, setShowChangePw] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  // Whether the browser has exempted this origin from storage eviction. Since the
  // keystore is the only at-rest copy, a non-persisted origin risks losing it.
  const [persisted, setPersisted] = useState<boolean | null>(null);
  const [staySignedIn, setStay] = useState(isStaySignedIn());
  // Managed-account disclosure (whitepaper §13.8): true when the domain's DAR
  // declares admin key custody — the org admin holds this account's keys.
  const [managedDomain, setManagedDomain] = useState(false);

  useEffect(() => {
    if (!address) return;
    let cancelled = false;
    lookupIdentity(address)
      .then(r => { if (!cancelled) setManagedDomain(!!r.admin_key_custody); })
      .catch(() => { /* display-only badge; stay hidden on lookup failure */ });
    return () => { cancelled = true; };
  }, [address]);

  // Backup download button label. Exporting needs the raw key bytes, which the
  // non-extractable session handles can't yield, so it re-unlocks the at-rest
  // keystore first — a passkey account taps their passkey, and a password account
  // choosing a passkey-protected backup enrolls one. Name that gesture up front so
  // the WebAuthn prompt isn't a surprise.
  const backupBtnLabel = busy ? 'Preparing…'
    : authMethod === 'passkey' ? 'Unlock and download'
    : exportMode === 'passkey' ? 'Create passkey and download'
    : 'Download backup';

  useEffect(() => {
    if (!address) return;
    loadLocalKeystore(address).then(ks => {
      setKeystore(ks);
      // Default the backup protection to match how the account is already secured: a
      // password account backs up with a passphrase, so exporting never springs a
      // surprise passkey enrollment. (The user can still switch to a passkey backup.)
      if (ks?.authMethod === 'password') setExportMode('password');
      else if (passkeyOk) setExportMode('passkey');
    });
  }, [address, passkeyOk]);
  useEffect(() => { isStoragePersisted().then(setPersisted); }, []);

  const enablePersistence = async () => {
    setPersisted(await requestPersistentStorage());
  };

  const exportBackup = async () => {
    if (!address) return;
    setBusy(true); setErr(''); setMsg('');
    try {
      if (exportMode === 'password' && !exportPw) throw new Error('choose a passphrase for the backup file');
      // Unlock the raw keys (passkey assertion, or the device password).
      const res = await unlockBackupBytes(address, authMethod === 'password' ? { password: exportCurrentPw } : undefined);

      let exp;
      if (exportMode === 'passkey') {
        // Reuse this device's passkey if it's the unlock method (no second prompt);
        // otherwise enroll a passkey to protect the backup.
        if (res.passkey) {
          exp = await buildPasskeyExport(address, res.kp, res.passkey);
        } else {
          const enr = await createPasskeyPRF(address);
          exp = await buildPasskeyExport(address, res.kp, { credentialId: enr.credentialId, prfSalt: enr.prfSalt, aesKey: enr.aesKey });
        }
        setMsg('Backup downloaded. It unlocks with your passkey — on any device where that passkey is available (e.g. via your synced keychain or password manager).');
      } else {
        exp = await buildPasswordExport(address, res.kp, exportPw);
        setMsg('Backup downloaded. Store it somewhere safe — it is encrypted with your chosen passphrase.');
      }
      triggerDownload(exp);
      setShowExport(false); setExportPw(''); setExportCurrentPw('');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'export failed');
    } finally { setBusy(false); }
  };

  const changePassword = async () => {
    if (!address) return;
    setBusy(true); setErr(''); setMsg('');
    try {
      if (!newPw) throw new Error('choose a new password');
      const { kp: rawKp } = await unlockBackupBytes(address, { password: curPw });
      const payload = new TextEncoder().encode(keyPairToPayloadJSON(rawKp));
      const bundle = await encryptKeys(payload, newPw);
      await saveLocalKeystore(makeLocalKeystore({ address, kp: rawKp, bundle, authMethod: 'password' }));
      setKeystore(await loadLocalKeystore(address));
      setMsg('Password changed for this device.');
      setShowChangePw(false); setCurPw(''); setNewPw('');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'password change failed');
    } finally { setBusy(false); }
  };
  // Appearance prefs go through lib/theme, which owns the storage keys (and their
  // per-context namespacing) — the shell reads exactly the same accessors.
  const [themePref, setThemePref] = useState<ThemePref>(readThemePref);
  const [density, setDensity] = useState<Density>(() => readDensity());

  // Effective light/dark for the standalone live page preview.
  const effectiveTheme = themePref === 'system' ? readTheme() : themePref;

  // Write the preference synchronously, then notify the shell to re-read it (so the
  // raw "system" pref is preserved and the shell re-themes immediately).
  const applyTheme = (t: ThemePref) => {
    writeThemePref(t);
    setThemePref(t);
    onAppearanceChange();
  };
  const applyDensity = (d: Density) => {
    writeDensity(d);
    setDensity(d);
    onAppearanceChange();
  };

  // Seed the forms from the synced settings doc when it (re)loads.
  useEffect(() => {
    setSignature(settings.signature ?? '');
    setComposePlainText(settings.composePlainText === true);
    setRemoteImages(settings.remoteImagesForTrusted === true);
  }, [settings.signature, settings.composePlainText, settings.remoteImagesForTrusted]);

  // Optimistic, and reverted on failure: the switch must never show "on" while mail is
  // still blocking images (or the reverse) — the user would draw the wrong conclusion
  // about what their client just did.
  const applyRemoteImages = async (v: boolean) => {
    const prev = remoteImages;
    setRemoteImages(v);
    setRemoteImagesErr('');
    try {
      await updateSettings({ remoteImagesForTrusted: v });
    } catch (e) {
      setRemoteImages(prev);
      setRemoteImagesErr(e instanceof Error ? e.message : 'Could not save that setting.');
    }
  };

  const saveProfile = async () => {
    setProfileBusy(true);
    setProfileMsg('');
    try {
      await updateSettings({ signature, composePlainText });
      setProfileMsg('Saved. Your profile syncs to your other devices.');
    } catch (e) {
      setProfileMsg(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setProfileBusy(false);
    }
  };

  // Fingerprint: first 20 bytes of SHA-256(Ed25519Public || X25519Public).
  useEffect(() => {
    if (!keys) return;
    const data = new Uint8Array(64);
    data.set(keys.ed25519Public, 0);
    data.set(keys.x25519Public, 32);
    crypto.subtle.digest('SHA-256', data).then(hash => {
      setFingerprint(toHex(new Uint8Array(hash).slice(0, 20)).toUpperCase());
    });
  }, [keys]);

  const grouped = (fingerprint.match(/.{1,4}/g) || []).join('·');

  // Sign out locks this account on this device: it drops the working handles (so the
  // account re-locks) and ends the session. The encrypted keystore stays, so the
  // account still appears on the unlock screen. Other tabs/accounts are untouched.
  const handleSignOut = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    await clearKeys();
    clearSession();
    navigate('/login');
  };

  return (
    <PageShell embedded={embedded} title="Settings" theme={effectiveTheme} density={density}>
      <div style={{ maxWidth: 820, margin: '0 auto', padding: 'var(--space-8)' }}>
        <Tabs
          value={section}
          onChange={v => setSection(v as Section)}
          items={[
            { value: 'profile', label: 'Profile', icon: <Icon name="user" size={16} /> },
            { value: 'privacy', label: 'Privacy & security', icon: <Icon name="shield" size={16} /> },
            { value: 'appearance', label: 'Appearance', icon: <Icon name="sun" size={16} /> },
            { value: 'account', label: 'Account', icon: <Icon name="user" size={16} /> },
          ]}
        />

        {section === 'profile' && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <div style={{ padding: 'var(--space-4) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Signature</div>
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2, marginBottom: 'var(--space-3)' }}>
                Appended to new messages you compose. Synced across your devices.
              </div>
              <Textarea value={signature} onChange={e => setSignature(e.target.value)} rows={4} placeholder="— Sent securely over dmcn" aria-label="Signature" />
            </div>
            <Row
              title="Compose in plain text"
              desc="New messages and replies start in plain text. You can still switch any single message to rich text."
            >
              <Switch checked={composePlainText} onChange={setComposePlainText} />
            </Row>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginTop: 'var(--space-4)' }}>
              <Button onClick={saveProfile} disabled={profileBusy}>{profileBusy ? 'Saving…' : 'Save profile'}</Button>
              {profileMsg && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{profileMsg}</span>}
            </div>
          </div>
        )}

        {section === 'privacy' && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <div style={{ padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
                <Icon name="key" size={16} style={{ color: 'var(--brand)' }} />
                <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Your encryption key</span>
                {keys && <Badge variant="success" dot>Active</Badge>}
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-body)', background: 'var(--surface-sunken)', padding: 'var(--space-3)', letterSpacing: '0.04em', wordBreak: 'break-all' }}>
                {grouped || 'Computing…'}
              </div>
              <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
                Private keys are stored as non-extractable keys in your browser and never leave it. The server holds no
                copy of your keys — not even encrypted. All encryption and signing happens client-side.
              </p>
            </div>

            <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
                <Icon name="shield-check" size={16} style={{ color: 'var(--brand)' }} />
                <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Backup &amp; recovery</span>
              </div>
              <p style={{ margin: '0 0 var(--space-3)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
                Because the server keeps no copy of your keys, losing every device means losing this identity. Download an
                encrypted backup file and keep it somewhere safe — it can restore your identity on a new device.
              </p>

              {persisted === false && (
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} />
                  <span>
                    This browser hasn't granted persistent storage, so it may evict your keys under disk pressure (or, on
                    Safari, after ~7 days of not opening the app). <strong>Download a backup below.</strong>{' '}
                    <button type="button" onClick={() => void enablePersistence()} style={{ background: 'none', border: 'none', padding: 0, font: 'inherit', color: 'var(--text-link)', textDecoration: 'underline', cursor: 'pointer' }}>Try enabling persistent storage</button>.
                  </span>
                </div>
              )}
              {persisted === true && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                  <Icon name="shield-check" size={15} style={{ color: 'var(--brand)' }} />
                  Persistent storage is enabled — your keys won't be evicted by the browser.
                </div>
              )}
              {msg && <div style={{ marginBottom: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>{msg}</div>}
              {err && <div style={{ marginBottom: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>{err}</div>}

              {!showExport ? (
                <Button size="sm" variant="secondary" onClick={() => { setShowExport(true); setShowChangePw(false); setErr(''); setMsg(''); }}>
                  Export encrypted backup…
                </Button>
              ) : (
                <form onSubmit={e => { e.preventDefault(); void exportBackup(); }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
                  {passkeyOk && (
                    <div>
                      <label style={{ fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', display: 'block', marginBottom: 'var(--space-2)' }}>Protect the backup with</label>
                      <div style={{ display: 'flex' }}>
                        <SegOption active={exportMode === 'passkey'} onClick={() => setExportMode('passkey')}>Passkey</SegOption>
                        <SegOption active={exportMode === 'password'} onClick={() => setExportMode('password')}>Passphrase</SegOption>
                      </div>
                    </div>
                  )}
                  {authMethod === 'password' && (
                    <Input label="Current device password" type="password" value={exportCurrentPw} onChange={e => setExportCurrentPw(e.target.value)} />
                  )}
                  {exportMode === 'password' ? (
                    <Input label="Backup passphrase" type="password" value={exportPw} onChange={e => setExportPw(e.target.value)} hint="Encrypts the backup file. You'll need it to restore." autoFocus />
                  ) : (
                    <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
                      The backup unlocks with your passkey. It will open on any device where that passkey is available —
                      with a synced passkey (iCloud Keychain, Google Password Manager, a password manager) that's all your
                      devices; with a device-bound security key, only that key. Keep a passphrase backup too if you're unsure.
                    </p>
                  )}
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <Button size="sm" type="submit" disabled={busy}>{backupBtnLabel}</Button>
                    <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={() => { setShowExport(false); setExportPw(''); setExportCurrentPw(''); }}>Cancel</Button>
                  </div>
                </form>
              )}

              {authMethod === 'password' && (
                <div style={{ marginTop: 'var(--space-3)' }}>
                  {!showChangePw ? (
                    <Button size="sm" variant="secondary" onClick={() => { setShowChangePw(true); setShowExport(false); setErr(''); setMsg(''); }}>
                      Change device password…
                    </Button>
                  ) : (
                    <form onSubmit={e => { e.preventDefault(); void changePassword(); }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                      <Input label="Current password" type="password" value={curPw} onChange={e => setCurPw(e.target.value)} autoFocus />
                      <Input label="New password" type="password" value={newPw} onChange={e => setNewPw(e.target.value)} />
                      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                        <Button size="sm" type="submit" disabled={busy}>{busy ? 'Updating…' : 'Change password'}</Button>
                        <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={() => { setShowChangePw(false); setCurPw(''); setNewPw(''); }}>Cancel</Button>
                      </div>
                    </form>
                  )}
                </div>
              )}
            </div>

            <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)', display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Stay signed in after closing the browser</div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2, lineHeight: 'var(--leading-normal)' }}>
                  Off (recommended): each tab unlocks on its own and locks when closed, so reopening needs your passkey or
                  password — a page refresh never re-prompts. On: accounts stay unlocked across browser restarts for
                  one-click access.
                </div>
              </div>
              <Switch checked={staySignedIn} onChange={v => { setStaySignedIn(v); setStay(v); }} />
            </div>

            <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Load remote images from senders you trust</div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2, lineHeight: 'var(--leading-normal)' }}>
                    Off (recommended): images hosted on a sender's server are never fetched, so opening a message tells
                    them nothing. On: they load for senders on your allowlist only — pending and blocked senders stay
                    blocked either way. A remote image is how ordinary mail measures whether, when and where you opened
                    it, so turning this on hands that back to people you have already decided to trust.
                  </div>
                </div>
                <Switch checked={remoteImages} onChange={v => void applyRemoteImages(v)} />
              </div>
              {remoteImagesErr && (
                <div style={{ marginTop: 'var(--space-3)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>{remoteImagesErr}</div>
              )}
            </div>

            {keys && <BlockedSenders keys={keys} />}
          </div>
        )}

        {section === 'appearance' && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <Row title="Theme" desc="Light, dark, or follow your system setting.">
              <div style={{ display: 'flex' }}>
                <SegOption active={themePref === 'light'} onClick={() => applyTheme('light')}>Light</SegOption>
                <SegOption active={themePref === 'dark'} onClick={() => applyTheme('dark')}>Dark</SegOption>
                <SegOption active={themePref === 'system'} onClick={() => applyTheme('system')}>System</SegOption>
              </div>
            </Row>
            <Row title="Density" desc="Comfortable spacing, or compact to fit more messages per screen.">
              <div style={{ display: 'flex' }}>
                <SegOption active={density === 'comfortable'} onClick={() => applyDensity('comfortable')}>Comfortable</SegOption>
                <SegOption active={density === 'compact'} onClick={() => applyDensity('compact')}>Compact</SegOption>
              </div>
            </Row>
          </div>
        )}

        {section === 'account' && (
          <div style={{ marginTop: 'var(--space-6)', display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
            <p style={{ margin: 0, fontSize: 'var(--text-md)', color: 'var(--text-muted)' }}>
              Manage your identity, plan and session on this device.
            </p>

            <StorageCard />

            <section style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <SectionHeading title="Mailbox" />
              <RowGroup>
                <Row grouped title="Signed in as" desc="This identity signs and decrypts your mail.">
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-body)', whiteSpace: 'nowrap' }}>{address}</span>
                </Row>
                {managedDomain ? (
                  <Row grouped title="Managed account" desc="Keys for this account are held by your domain administrator. Account recovery and new devices are set up through them (device pairing).">
                    <Badge variant="neutral"><Icon name="shield-check" size={13} /> Managed</Badge>
                  </Row>
                ) : null}
                <Row grouped title="Switch or add account" desc="Use another identity in this tab, or add a new one.">
                  <Button variant="secondary" size="sm" leftIcon={<Icon name="users" size={15} />} onClick={() => navigate('/login')}>Switch account</Button>
                </Row>
                <Row grouped title="Sign out" desc="Locks this account on this device and ends the session. It stays available to unlock again.">
                  <Button variant="danger" size="sm" leftIcon={<Icon name="log-out" size={15} />} onClick={handleSignOut}>Sign out</Button>
                </Row>
              </RowGroup>
            </section>
          </div>
        )}

        <div style={{ marginTop: 'var(--space-6)', fontSize: 'var(--text-xs)', color: 'var(--text-subtle)' }}>
          DMCN Mail <span style={{ fontFamily: 'var(--font-mono)' }}>{APP_VERSION}</span>
        </div>
      </div>
    </PageShell>
  );
}
