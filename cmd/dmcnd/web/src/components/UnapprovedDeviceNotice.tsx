// What a browser sees when it holds the account's keys but is not one of its enrolled devices.
//
// Two ways to get here: this browser never paired (the account enrolled a device somewhere else
// first), or it was removed from another device. Either way the keys alone open nothing, and the
// way back is the pairing ceremony, approved from a device the account still has. Where this
// deployment has no pairing, the notice says what is wrong and stops there.

import { useNavigate } from 'react-router-dom';
import { deployment } from '@deployment';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { logout as apiLogout } from '../lib/api/client';
import { Button } from '../ds';
import { Icon } from './Icon';

export function UnapprovedDeviceNotice({ address, inline }: {
  address: string;
  /** Inside a card that already has its own padding (the Devices panel), rather than in a list. */
  inline?: boolean;
}) {
  const navigate = useNavigate();
  const { clearSession } = useAuth();
  const { clearKeys } = useKeys();
  const pairing = deployment.pairing;

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

  return (
    <div role="alert" style={{
      display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)', margin: inline ? 0 : 'var(--space-4)', padding: 'var(--space-4)',
      background: 'var(--warning-subtle)', color: 'var(--text-body)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)',
    }}>
      <Icon name="monitor" size={16} style={{ color: 'var(--warning)', marginTop: 2, flex: 'none' }} />
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', lineHeight: 'var(--leading-normal)' }}>
        <div>
          <strong>This browser is not approved for {address}.</strong>{' '}
          It has the account&rsquo;s keys, but the mailbox only opens on devices you have approved. That happens if
          this browser was never paired, or if it was removed from another device.
        </div>
        {pairing ? (
          <>
            <div>
              To use it again, pair it: you will see a code here and type its last four digits on a device that
              still has access.
            </div>
            <div><Button size="sm" onClick={() => void pairAgain()}>Pair this browser</Button></div>
          </>
        ) : (
          <div>Approve it from a device that still has access.</div>
        )}
      </div>
    </div>
  );
}
