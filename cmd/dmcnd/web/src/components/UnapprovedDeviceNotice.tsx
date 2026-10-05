// What a browser sees when it holds the account's keys but is not one of its enrolled devices.
//
// Two ways to get here: this browser never paired (the account enrolled a device somewhere else
// first, or the keys came from a backup file), or it was removed from another device. Either way
// the keys alone open nothing. The way back is the pairing ceremony, approved from a device the
// account still has. Where this deployment has no pairing, the notice says what is wrong and stops
// there.
//
// For someone whose every other device is gone there is a second, slower way: this browser asks to
// join on its own (requestRecovery). The request waits out the domain's delay in the open, every
// device still on the account sees it, and any of them can cancel it. It is offered only on a
// deliberate click, below the pairing route, because a browser asking on every sign-in would bury
// a real hostile request among the owner's own.

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { deployment } from '@deployment';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { logout as apiLogout } from '../lib/api/client';
import {
  describeBrowser, rememberedRecovery, requestRecovery, sealDeviceLabel, signerFor, type RecoveryState,
} from '../lib/api/deviceRegistry';
import { Button, Dialog } from '../ds';
import { Icon } from './Icon';

/** A recovery date as a person reads it: the day and the time it opens. */
function whenItOpens(sec: number): string {
  return new Date(sec * 1000).toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' });
}

type View =
  | { kind: 'idle' }
  | { kind: 'waiting'; eligibleAt: number }
  | { kind: 'cancelled' }
  | { kind: 'disabled' }
  | { kind: 'failed' };

/** What the notice shows after a recovery request (or a check on an earlier one) answers. */
function viewFor(r: RecoveryState, remembered: number | null): View {
  switch (r.state) {
    case 'waiting': return { kind: 'waiting', eligibleAt: r.eligibleAt };
    case 'already-asked': return remembered ? { kind: 'waiting', eligibleAt: remembered } : { kind: 'idle' };
    case 'cancelled': return { kind: 'cancelled' };
    case 'disabled': return { kind: 'disabled' };
    default: return { kind: 'failed' };
  }
}

export function UnapprovedDeviceNotice({ address, inline }: {
  address: string;
  /** Inside a card that already has its own padding (the Devices panel), rather than in a list. */
  inline?: boolean;
}) {
  const navigate = useNavigate();
  const { clearSession } = useAuth();
  const { keys, clearKeys } = useKeys();
  const pairing = deployment.pairing;
  // Recovery exists where devices are approved by pairing: that is the deployment with a device
  // registry. Without pairing there is no registry, and nothing to recover into.
  const recoveryOffered = !!pairing && !!keys && keys.address === address;

  const [view, setView] = useState<View>(() => {
    const at = rememberedRecovery(address);
    return at ? { kind: 'waiting', eligibleAt: at } : { kind: 'idle' };
  });
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  // A browser that already asked checks its request still stands: it cannot list the registry
  // while it waits, so asking again is the only question it can put, and the relay answers it
  // without making a second request ("already enrolled", or "removed" if it was cancelled).
  useEffect(() => {
    if (!recoveryOffered || !keys) return;
    const remembered = rememberedRecovery(address);
    if (!remembered) return;
    let cancelled = false;
    void requestRecovery(signerFor(keys)).then(r => { if (!cancelled) setView(viewFor(r, remembered)); });
    return () => { cancelled = true; };
  }, [address, keys, recoveryOffered]);

  // Pairing runs signed out: it stands up a short-lived identity of its own for the approval to
  // arrive at, and this session cannot read the mailbox anyway. The keystore stays, so nothing is
  // lost if the pairing is abandoned.
  //
  // Leave the shell FIRST. Dropping the keys while still inside it lets the signed-in guard see
  // no keys and send the tab to sign-in before this navigation happens.
  const pairAgain = async () => {
    if (!pairing) return;
    navigate(`${pairing.path}?address=${encodeURIComponent(address)}`);
    try { await apiLogout(); } catch { /* the session ends either way */ }
    await clearKeys();
    clearSession();
  };

  const askToJoin = async () => {
    if (!keys) return;
    setBusy(true);
    try {
      const label = await sealDeviceLabel(describeBrowser(navigator.userAgent), keys.x25519Public);
      setView(viewFor(await requestRecovery(signerFor(keys), label), rememberedRecovery(address)));
    } finally {
      setBusy(false);
      setConfirming(false);
    }
  };

  const now = Math.floor(Date.now() / 1000);
  const waiting = view.kind === 'waiting' ? view : null;

  return (
    <div role="alert" style={{
      display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)', margin: inline ? 0 : 'var(--space-4)', padding: 'var(--space-4)',
      background: 'var(--warning-subtle)', color: 'var(--text-body)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)',
    }}>
      <Icon name={waiting ? 'clock' : 'monitor'} size={16} style={{ color: 'var(--warning)', marginTop: 2, flex: 'none' }} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', lineHeight: 'var(--leading-normal)' }}>
        {waiting && now >= waiting.eligibleAt ? (
          <>
            <div><strong>The wait is over.</strong> Reload to open your mail on this browser.</div>
            <div><Button size="sm" onClick={() => window.location.reload()}>Reload</Button></div>
          </>
        ) : waiting ? (
          <>
            <div data-testid="recovery-waiting">
              <strong>This browser can open your mail from {whenItOpens(waiting.eligibleAt)}.</strong>{' '}
              If you find another device before then, you can still pair from it.
            </div>
            {pairing && <div><Button size="sm" variant="secondary" onClick={() => void pairAgain()}>Pair this browser</Button></div>}
          </>
        ) : (
          <>
            <div>
              <strong>This browser is not approved for {address}.</strong>{' '}
              It has the account&rsquo;s keys, but the mailbox only opens on devices you have approved. That happens if
              this browser was never paired, if the keys came from a backup file, or if it was removed from another device.
            </div>
            {view.kind === 'cancelled' && (
              <div><strong>Another device on this account cancelled this browser&rsquo;s request to join.</strong></div>
            )}
            {view.kind === 'disabled' && (
              <div>This account does not let a browser join without approval from another device.</div>
            )}
            {view.kind === 'failed' && (
              <div>The request to join could not be sent. Try again in a moment.</div>
            )}
            {pairing ? (
              <>
                <div>
                  To use it, pair it: you will see a code here and type its last four digits on a device that
                  still has access.
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                  <Button size="sm" onClick={() => void pairAgain()}>Pair this browser</Button>
                  {recoveryOffered && view.kind !== 'cancelled' && view.kind !== 'disabled' && (
                    <Button size="sm" variant="secondary" onClick={() => setConfirming(true)}>I don&rsquo;t have another device</Button>
                  )}
                </div>
              </>
            ) : (
              <div>Approve it from a device that still has access.</div>
            )}
          </>
        )}
      </div>

      <Dialog
        open={confirming}
        title="Join without another device?"
        onClose={() => { if (!busy) setConfirming(false); }}
        maxWidth={480}
        footer={
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirming(false)}>Cancel</Button>
            <Button size="sm" disabled={busy} onClick={() => void askToJoin()}>{busy ? 'Asking…' : 'Ask to join'}</Button>
          </div>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-normal)', color: 'var(--text-muted)' }}>
          <p style={{ margin: 0 }}>
            If every other device on this account is gone, this browser can ask to join on its own.
          </p>
          <p style={{ margin: 0 }}>
            It has to wait before it can open your mail. Any device still on the account will see the request in its
            list of devices and can cancel it during that time.
          </p>
          <p style={{ margin: 0 }}>
            If you still have another device, pair from it instead. It is quicker, and nothing has to wait.
          </p>
        </div>
      </Dialog>
    </div>
  );
}
