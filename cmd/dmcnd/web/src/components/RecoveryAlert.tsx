// The other half of recovery: the devices still on an account have to SEE a request to join
// without approval, or the veto it depends on is only theoretical. Shown in the inbox of an active
// device while any device on the account is inside its recovery wait, with the way to the device
// list where removing it cancels the request. Supplied through deployment.accountNotice
// (AccountNotices), so the demo front door, which has no device list, never shows it.
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useKeys } from '../lib/hooks/useKeys';
import { listDevices, signerFor, waitingDevices } from '../lib/api/deviceRegistry';
import { Button } from '../ds';
import { Icon } from './Icon';

function whenItOpens(sec: number): string {
  return new Date(sec * 1000).toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' });
}

export function RecoveryAlert({ address }: { address: string }) {
  const navigate = useNavigate();
  const { keys } = useKeys();
  // The earliest a waiting device could act, or null when none is waiting.
  const [opensAt, setOpensAt] = useState<number | null>(null);

  const check = useCallback(() => {
    if (!keys || keys.address !== address) return;
    listDevices(signerFor(keys))
      .then(devices => {
        const waiting = waitingDevices(devices, Math.floor(Date.now() / 1000));
        setOpensAt(waiting.length ? Math.min(...waiting.map(d => d.eligible_at ?? 0)) : null);
      })
      // Listing needs this browser to be an active device; one that is not sees its own notice
      // instead, and a relay that cannot answer just means nothing to report this time.
      .catch(() => setOpensAt(null));
  }, [address, keys]);

  // On open and whenever the window comes back: gentle, and enough for a wait measured in days.
  useEffect(() => {
    check();
    window.addEventListener('focus', check);
    return () => window.removeEventListener('focus', check);
  }, [check]);

  if (opensAt === null) return null;
  return (
    <div
      role="alert"
      data-testid="recovery-alert"
      style={{
        display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap',
        padding: 'var(--space-3) var(--space-4)', background: 'var(--warning-subtle)', color: 'var(--text-body)',
        borderBottom: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)',
      }}
    >
      <Icon name="monitor" size={16} style={{ color: 'var(--warning)', flex: 'none' }} />
      <span style={{ flex: '1 1 16rem', minWidth: 0 }}>
        <strong>A device asked to join your account without approval.</strong>{' '}
        It can open your mail from {whenItOpens(opensAt)} unless you remove it.
      </span>
      <Button size="sm" variant="secondary" onClick={() => navigate('/settings?section=privacy')}>Review devices</Button>
    </div>
  );
}
