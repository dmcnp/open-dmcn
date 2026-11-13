import { useEffect, useRef, useState } from 'react';
import { unlockBackupBytes } from '../lib/crypto/reauth';
import { buildPasscodeExport, exportFileName, exportUsername, triggerDownload } from '../lib/crypto/exportFile';
import { generatePasscode } from '../lib/crypto/passcode';
import type { IdentityKeyPair } from '../lib/crypto/keys';
import { Button, Dialog, IconButton, Input } from '../ds';
import { Icon } from './Icon';
import { CopyButton } from './CopyButton';

// "Export my key to an encrypted file": the key, encrypted under a passcode this page generates
// (crypto/passcode.ts), saved as a file on this device.
//
// One button, then one dialog that moves through the steps:
//
//   unlock    a passphrase-protected device asks for its password here. A passkey device skips
//             this step: the button itself triggers the passkey prompt, which is its own dialog.
//   passcode  the passcode, in a username + new-password form. Pressing Export submits it, which
//             is the moment a password manager offers to save the passcode.
//   exported  the file is saved; the passcode stays on screen for anyone writing it down, and
//             the only way out is saying it is stored. No ×, Escape or backdrop close here: this
//             is the last time the passcode exists anywhere, so leaving is a deliberate act.
//
// The unlock and passcode forms are separate on purpose. A device password and a new password in
// one form reads to a password manager as a password CHANGE, and it could overwrite the saved
// device password with the passcode. For the same reason the passcode is saved under its own
// username (exportUsername), not the bare address.

type Step = 'closed' | 'unlock' | 'passcode' | 'exported';

export function KeyExport({ address, authMethod, onExported }: {
  address: string;
  authMethod: 'password' | 'passkey' | null;
  onExported: (message: string) => void;
}) {
  const [step, setStep] = useState<Step>('closed');
  const [devicePw, setDevicePw] = useState('');
  const [passcode, setPasscode] = useState('');
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  // The unlocked keys, held only between unlocking and exporting. Not state: nothing renders from
  // them, and a ref keeps them out of React's devtools snapshots.
  const keys = useRef<IdentityKeyPair | null>(null);
  useEffect(() => () => { keys.current = null; }, []);

  const close = () => {
    keys.current = null;
    setStep('closed'); setDevicePw(''); setPasscode(''); setReveal(false); setErr('');
  };

  const unlock = async () => {
    setBusy(true); setErr('');
    try {
      const res = await unlockBackupBytes(address, authMethod === 'password' ? { password: devicePw } : undefined);
      keys.current = res.kp;
      setDevicePw('');
      setPasscode(generatePasscode());
      setStep('passcode');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not unlock your key');
    } finally { setBusy(false); }
  };

  const start = () => {
    setErr('');
    // A passkey prompt is already a dialog of its own; a second one in front of it adds nothing.
    if (authMethod === 'password') setStep('unlock');
    else void unlock();
  };

  const exportKey = async () => {
    if (!keys.current) { close(); return; }
    setBusy(true); setErr('');
    try {
      triggerDownload(await buildPasscodeExport(address, keys.current, passcode));
      keys.current = null;
      // Replacing the submitted form is what tells a browser's password manager the submit
      // succeeded, so this follows the submit rather than preceding it.
      setStep('exported');
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'export failed');
    } finally { setBusy(false); }
  };

  const finish = () => {
    onExported(`Your key was exported to ${exportFileName(address)}.`);
    close();
  };

  const errorRow = err && (
    <div role="alert" style={{ padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>{err}</div>
  );
  const important = (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-strong)', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-normal)', borderRadius: 'var(--radius-md)' }}>
      <Icon name="alert-triangle" size={15} style={{ marginTop: 2, flex: 'none', color: 'var(--warning)' }} />
      <span>
        <strong>Important:</strong> store this passcode somewhere safe, such as your password manager or on paper.
        It is the only way to open the exported file, and nobody can recover it for you. Keep it apart from the file.
      </span>
    </div>
  );
  const body = { display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' } as const;
  const muted = { margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' } as const;
  const actions = { display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end', marginTop: 'var(--space-2)' } as const;

  const title = step === 'unlock' ? 'Unlock your key'
    : step === 'passcode' ? 'Export your key'
      : 'Key exported';
  // Before anything is exported, closing just closes. After, only the confirming button closes.
  const onClose = step === 'exported' || busy ? undefined : close;

  return (
    <>
      <Button size="sm" variant="secondary" leftIcon={<Icon name="key" size={14} />} onClick={start} disabled={busy && step === 'closed'}>
        {busy && step === 'closed' ? 'Unlocking…' : 'Export my key to an encrypted file'}
      </Button>
      {step === 'closed' && err && <div style={{ marginTop: 'var(--space-3)' }}>{errorRow}</div>}

      <Dialog open={step !== 'closed'} onClose={onClose} title={title} maxWidth={480}>
        {step === 'unlock' && (
          <form onSubmit={e => { e.preventDefault(); void unlock(); }} style={body}>
            <p style={muted}>Enter this device’s password to unlock your key for export.</p>
            {/* Names the account for a password manager filling the field below. */}
            <input type="text" name="username" autoComplete="username" defaultValue={address} tabIndex={-1} aria-hidden="true" style={visuallyHidden} />
            <Input label="Device password" type="password" name="password" autoComplete="current-password" value={devicePw} onChange={e => setDevicePw(e.target.value)} autoFocus />
            {errorRow}
            <div style={actions}>
              <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={close}>Cancel</Button>
              <Button size="sm" type="submit" disabled={busy || !devicePw}>{busy ? 'Unlocking…' : 'Continue'}</Button>
            </div>
          </form>
        )}

        {step === 'passcode' && (
          <form onSubmit={e => { e.preventDefault(); void exportKey(); }} style={body}>
            <p style={muted}>
              Your key is saved to a file on this device, encrypted with the passcode below. To bring it back on
              another device you need both the file and the passcode.
            </p>
            {/* The username + new-password pair is what a password manager recognises as "save
                this". Visually hidden but present: managers skip display:none fields. */}
            <input type="text" name="username" autoComplete="username" defaultValue={exportUsername(address)} tabIndex={-1} aria-hidden="true" style={visuallyHidden} />
            <Input
              label="Passcode"
              name="password"
              type={reveal ? 'text' : 'password'}
              autoComplete="new-password"
              value={passcode}
              // Not readOnly: some password managers will not save a read-only field. Edits are
              // ignored, because a passcode someone retyped is no longer the random one made here.
              onChange={() => {}}
              spellCheck={false}
              // Sized to fit all 29 characters beside the two buttons on a phone-width dialog.
              style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-md)' }}
              trailingAction={
                <span style={{ display: 'flex' }}>
                  <IconButton variant="ghost" size="sm" type="button" aria-label={reveal ? 'Hide passcode' : 'Show passcode'} onClick={() => setReveal(r => !r)}>
                    <Icon name={reveal ? 'eye-off' : 'eye'} size={16} />
                  </IconButton>
                  <CopyButton value={passcode} what="passcode" />
                </span>
              }
              hint="If you use a password manager, it should offer to save the passcode when you press Export."
            />
            {important}
            {errorRow}
            <div style={actions}>
              <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={close}>Cancel</Button>
              <Button size="sm" type="submit" disabled={busy}>{busy ? 'Exporting…' : 'Export'}</Button>
            </div>
          </form>
        )}

        {step === 'exported' && (
          <div style={body}>
            <p style={muted}>
              Saved on this device as <code style={{ fontFamily: 'var(--font-mono)' }}>{exportFileName(address)}</code>.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', background: 'var(--surface-sunken)' }}>
              <span data-testid="export-passcode" style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-md)', letterSpacing: '0.04em', color: 'var(--text-strong)', userSelect: 'all' }}>{passcode}</span>
              <CopyButton value={passcode} what="passcode" />
            </div>
            {important}
            <p style={muted}>This is the last time the passcode is shown.</p>
            <div style={actions}>
              <Button size="sm" type="button" onClick={finish}>I’ve stored the passcode somewhere safe</Button>
            </div>
          </div>
        )}
      </Dialog>
    </>
  );
}

const visuallyHidden = {
  position: 'absolute', width: 1, height: 1, padding: 0, margin: -1, overflow: 'hidden',
  clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', border: 0,
} as const;
