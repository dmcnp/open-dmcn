// The devices that may open this mailbox, in Privacy & security.
//
// The account key says whose mailbox this is; the device list says where it may be opened. Every
// browser or phone that paired is on it, named as it named itself, with the date it joined. From
// here the owner can remove any device other than the one they are holding, and a removed device
// stays on the list, marked, because a removal is something the owner needs to be able to notice
// if it was not theirs.
//
// A removed device can come back only by pairing again, approved from a device that still has
// access, and it comes back as a new entry: the relay refuses the removed key for good.
//
// Product-only, reached through the deployment seam: the reference daemon keeps no device list.

import { useCallback, useEffect, useState } from 'react';
import { Badge, Button, Dialog } from '../ds';
import { Icon } from './Icon';
import { UnapprovedDeviceNotice } from './UnapprovedDeviceNotice';
import { loadDeviceKey } from '../lib/crypto/deviceKey';
import { fromBase64, toBase64 } from '../lib/crypto/keys';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { formatDate } from '../lib/format';
import {
  deviceStanding, isUnapprovedDevice, listDevices, openDeviceLabel, retireDevice, signerFor,
  type DeviceRecord, type DeviceStanding,
} from '../lib/api/deviceRegistry';
import { orderDevices } from '../lib/devices';

const muted = { fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' } as const;

interface Row {
  record: DeviceRecord;
  name: string;
  standing: DeviceStanding;
  mine: boolean;
}

type State =
  | { kind: 'loading' }
  | { kind: 'rows'; rows: Row[] }
  | { kind: 'unapproved' }
  | { kind: 'unsupported' }
  | { kind: 'failed'; message: string };

export function DeviceManager({ address, keys }: { address: string; keys: WorkingKeys }) {
  const [state, setState] = useState<State>({ kind: 'loading' });
  const [confirm, setConfirm] = useState<Row | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [showRemoved, setShowRemoved] = useState(false);

  const load = useCallback(async () => {
    try {
      const [records, mine] = await Promise.all([listDevices(signerFor(keys)), loadDeviceKey(address)]);
      const minePub = mine ? toBase64(mine.publicKey) : '';
      const now = Math.floor(Date.now() / 1000);
      const rows = await Promise.all(records.map(async record => ({
        record,
        name: await openDeviceLabel(record.sealed_label, keys),
        standing: deviceStanding(record, now),
        mine: record.public === minePub,
      })));
      setState({ kind: 'rows', rows: orderDevices(rows) });
    } catch (err) {
      if (isUnapprovedDevice(err)) { setState({ kind: 'unapproved' }); return; }
      const message = err instanceof Error ? err.message : String(err);
      // A mailbox whose relay keeps no device list has nothing to show here, which is an answer
      // rather than a failure.
      if (message.includes('does not host a device registry')) { setState({ kind: 'unsupported' }); return; }
      setState({ kind: 'failed', message });
    }
  }, [address, keys]);

  useEffect(() => { void load(); }, [load]);

  const remove = async (row: Row) => {
    setBusy(true); setError('');
    try {
      await retireDevice(address, signerFor(keys), fromBase64(row.record.public));
      setConfirm(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove that device.');
    } finally {
      setBusy(false);
    }
  };

  if (state.kind === 'unsupported') return null;

  const rows = state.kind === 'rows' ? state.rows : [];
  const current = rows.filter(r => r.standing !== 'removed');
  const removed = rows.filter(r => r.standing === 'removed');
  // Only an active device may remove another, and the relay checks it too. The list is readable
  // at all only from an active device (or while the account has none), so this is almost always
  // true; it is false on an account whose list is still empty.
  const canRemove = rows.some(r => r.mine && r.standing === 'active');

  return (
    <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
        <Icon name="monitor" size={16} style={{ color: 'var(--brand)' }} />
        <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Your devices</span>
      </div>
      <p style={{ ...muted, margin: '0 0 var(--space-3)' }}>
        Your mailbox opens only on these devices. Your keys on their own are not enough, so a copy of them
        somewhere else cannot read your mail. Add a device by pairing it from one of these.
      </p>

      {state.kind === 'loading' && <div style={muted}>Loading your devices…</div>}
      {state.kind === 'unapproved' && <UnapprovedDeviceNotice address={address} inline />}
      {state.kind === 'failed' && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', ...muted }}>
          <span style={{ color: 'var(--danger)' }}>Could not load your devices: {state.message}</span>
          <Button size="sm" variant="secondary" onClick={() => { setState({ kind: 'loading' }); void load(); }}>Try again</Button>
        </div>
      )}
      {state.kind === 'rows' && rows.length === 0 && (
        <div style={muted}>No devices yet. This browser joins the list the next time the app opens.</div>
      )}

      {current.length > 0 && (
        <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}>
          {current.map((row, i) => (
            <DeviceRow key={row.record.public} row={row} first={i === 0}
              onRemove={canRemove && !row.mine ? () => { setError(''); setConfirm(row); } : undefined} />
          ))}
        </div>
      )}

      {removed.length > 0 && (
        <div style={{ marginTop: 'var(--space-3)' }}>
          <button type="button" onClick={() => setShowRemoved(v => !v)} style={{
            display: 'inline-flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', padding: 0,
            font: 'inherit', fontSize: 'var(--text-sm)', color: 'var(--text-link)', cursor: 'pointer',
          }}>
            <Icon name={showRemoved ? 'chevron-down' : 'chevron-right'} size={14} />
            {showRemoved ? 'Hide' : 'Show'} removed devices ({removed.length})
          </button>
          {showRemoved && (
            <div style={{ marginTop: 'var(--space-2)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}>
              {removed.map((row, i) => <DeviceRow key={row.record.public} row={row} first={i === 0} />)}
            </div>
          )}
        </div>
      )}

      {rows.length > 0 && !canRemove && state.kind === 'rows' && (
        <p style={{ ...muted, margin: 'var(--space-3) 0 0' }}>
          This browser is not on the list yet, so it cannot remove devices. It joins the next time the app opens.
        </p>
      )}

      <Dialog
        open={!!confirm}
        title={confirm ? `Remove ${confirm.name || 'this device'}?` : undefined}
        onClose={() => { if (!busy) setConfirm(null); }}
        maxWidth={480}
        footer={
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
            <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirm(null)}>Cancel</Button>
            <Button size="sm" variant="danger" disabled={busy} onClick={() => confirm && void remove(confirm)}>
              {busy ? 'Removing…' : 'Remove device'}
            </Button>
          </div>
        }
      >
        {confirm && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', ...muted }}>
            <p style={{ margin: 0 }}>
              It will stop being able to open this mailbox straight away. To use it again later, pair it from a
              device that still has access. It will show up here as a new device.
            </p>
            <p style={{ margin: 0 }}>
              It keeps the copy of your keys it already has. If it may be in someone else&rsquo;s hands, change your
              account key as well, under Account.
            </p>
            {error && <div style={{ color: 'var(--danger)' }}>{error}</div>}
          </div>
        )}
      </Dialog>
    </div>
  );
}

function DeviceRow({ row, first, onRemove }: { row: Row; first: boolean; onRemove?: () => void }) {
  const { record, standing } = row;
  const removed = standing === 'removed';
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-3)',
      borderTop: first ? 'none' : '1px solid var(--border-subtle)', opacity: removed ? 0.7 : 1,
    }}>
      <Icon name="monitor" size={16} style={{ color: 'var(--text-subtle)', flex: 'none' }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflowWrap: 'anywhere' }}>
            {row.name || 'Unnamed device'}
          </span>
          {row.mine && !removed && <Badge variant="brand">This browser</Badge>}
          {standing === 'waiting' && <Badge variant="warning">Not approved</Badge>}
          {removed && <Badge variant="neutral">Removed</Badge>}
        </div>
        <div style={{ ...muted, marginTop: 2 }}>
          {standing === 'waiting' && record.eligible_at
            ? <>Asked to join without approval from any of your devices. It can open your mail from {formatDate(record.eligible_at)}. If this was not you, remove it.</>
            : removed && record.retired_at
              ? <>Added {formatDate(record.enrolled_at)}, removed {formatDate(record.retired_at)}</>
              : <>Added {formatDate(record.enrolled_at)}</>}
        </div>
      </div>
      {onRemove && <Button size="sm" variant="secondary" onClick={onRemove}>Remove</Button>}
    </div>
  );
}
