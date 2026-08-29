import { useEffect, useState } from 'react';
import { emptyFilterList, type FilterList } from '../lib/api/filterList';
import { deployment } from '../deployment';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { Badge, Button, Input, Switch } from '../ds';
import { Icon } from './Icon';

// BlockedSenders edits the recipient's mail block/allow list. The list is held at
// the user's mailbox relay (so it silently drops blocked senders at delivery) but
// sealed to the owner's key + the relay's mailbox key — the server only sees
// ciphertext. Granularity: whole domains or specific sender addresses. Allow-list
// mode default-denies; "allow verified" then admits any DNS-anchored sender.
export function BlockedSenders({ keys }: { keys: WorkingKeys }) {
  const [client] = useState(() => deployment.mailFilter(keys));
  const [list, setList] = useState<FilterList | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [entry, setEntry] = useState('');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  useEffect(() => {
    let alive = true;
    client
      .get()
      .then((l) => { if (alive) setList(l ?? emptyFilterList()); })
      .catch((e) => { if (alive) setErr(e.message || 'failed to load filter'); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [client]);

  const persist = async (next: FilterList) => {
    setSaving(true); setMsg(''); setErr('');
    try {
      await client.save(next);
      setList(next);
      setMsg('Saved.');
    } catch (e) {
      setErr((e as Error).message || 'failed to save filter');
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Loading filters…</div>;
  if (!list) return null;

  // A value with an "@" is a specific sender; otherwise a whole domain.
  const addEntry = () => {
    const v = entry.trim().toLowerCase();
    if (!v) return;
    const next: FilterList = { ...list, domains: [...list.domains], senders: [...list.senders] };
    if (v.includes('@')) {
      if (!next.senders.includes(v)) next.senders.push(v);
    } else if (!next.domains.includes(v)) {
      next.domains.push(v);
    }
    setEntry('');
    void persist(next);
  };

  const removeDomain = (d: string) => void persist({ ...list, domains: list.domains.filter((x) => x !== d) });
  const removeSender = (s: string) => void persist({ ...list, senders: list.senders.filter((x) => x !== s) });
  const removeSenderKey = (k: string) => void persist({ ...list, sender_keys: (list.sender_keys ?? []).filter((x) => x !== k) });

  const isAllow = list.mode === 'allow';
  const blockedKeys = list.sender_keys ?? [];

  return (
    <div style={{ marginTop: 'var(--space-4)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', background: 'var(--surface-card)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <Icon name="shield" />
        <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>Blocked senders</span>
      </div>
      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)', lineHeight: 'var(--leading-normal)' }}>
        Your mailbox silently drops mail from these {isAllow ? 'unless allow-listed' : 'senders or domains'}. The list is
        encrypted to you and your mailbox; the operator can read only this list, never your messages.
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
        <div style={{ flex: 1, fontSize: 'var(--text-sm)', color: 'var(--text-strong)' }}>
          Allow-list mode (default-deny: keep only listed {isAllow ? '+ verified' : ''} senders)
        </div>
        <Switch checked={isAllow} onChange={(v) => void persist({ ...list, mode: v ? 'allow' : 'deny' })} />
      </div>
      {isAllow && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginBottom: 'var(--space-3)' }}>
          <div style={{ flex: 1, fontSize: 'var(--text-sm)', color: 'var(--text-strong)' }}>
            Also accept any domain-verified sender (DNS-anchored)
          </div>
          <Switch checked={!!list.allow_verified} onChange={(v) => void persist({ ...list, allow_verified: v })} />
        </div>
      )}

      <form onSubmit={(e) => { e.preventDefault(); addEntry(); }} style={{ display: 'flex', gap: 'var(--space-2)', marginBottom: 'var(--space-3)' }}>
        <Input
          label={isAllow ? 'Allow a sender or domain' : 'Block a sender or domain'}
          placeholder="spammer@example.com  or  example.com"
          value={entry}
          onChange={(e) => setEntry(e.target.value)}
        />
        <Button type="submit" disabled={saving || !entry.trim()}>Add</Button>
      </form>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        {list.senders.map((s) => (
          <Badge key={s} onClick={() => removeSender(s)} style={{ cursor: 'pointer' }} title="Remove">{s} ✕</Badge>
        ))}
        {list.domains.map((d) => (
          <Badge key={d} onClick={() => removeDomain(d)} style={{ cursor: 'pointer' }} title="Remove">@{d} ✕</Badge>
        ))}
        {list.senders.length === 0 && list.domains.length === 0 && (
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>Nothing {isAllow ? 'allow-listed' : 'blocked'} yet.</span>
        )}
      </div>

      {blockedKeys.length > 0 && (
        <div style={{ marginTop: 'var(--space-4)' }}>
          <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)', marginBottom: 'var(--space-1)' }}>Blocked identities</div>
          <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginBottom: 'var(--space-2)' }}>
            Bound to the sender's key, so they stay blocked even if they change address. Always dropped, regardless of allow/deny mode.
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
            {blockedKeys.map((k) => (
              <Badge key={k} variant="danger" onClick={() => removeSenderKey(k)} style={{ cursor: 'pointer', fontFamily: 'var(--font-mono)' }} title={`Remove — ${k}`}>
                {k.slice(0, 12)}… ✕
              </Badge>
            ))}
          </div>
        </div>
      )}

      {msg && <div style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-sm)', color: 'var(--brand-text)' }}>{msg}</div>}
      {err && <div style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{err}</div>}
    </div>
  );
}
