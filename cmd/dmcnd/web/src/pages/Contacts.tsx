import { useState } from 'react';
import { useContacts } from '../lib/hooks/useContacts';
import { lookupIdentity } from '../lib/api/client';
import { PageShell } from '../components/PageShell';
import { useIsMobile } from '../lib/useIsMobile';
import { DEFAULT_DOMAIN } from '../lib/config';
import { emailInputProps } from '../lib/emailInput';
import { Badge, Button, Dialog, IconButton, Input } from '../ds';
import { KindIcon } from '../components/KindIcon';
import { contactKind } from '../lib/trust/senderKind';
import { Icon } from '../components/Icon';
import { provenanceView } from '../lib/trust/trustView';

export function Contacts() {
  const { contacts, contactByAddress, addContact, removeContact } = useContacts();
  const embedded = !useIsMobile();
  const [q, setQ] = useState('');
  const [adding, setAdding] = useState(false);
  const [address, setAddress] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const filtered = contacts.filter(c => `${c.name} ${c.address}`.toLowerCase().includes(q.trim().toLowerCase()));

  const reset = () => { setAddress(''); setName(''); setError(''); };
  const close = () => { setAdding(false); reset(); };
  const canSave = address.trim().length > 0;

  const handleAdd = async () => {
    if (!canSave) return;
    setLoading(true);
    setError('');
    try {
      const identity = await lookupIdentity(address.trim());
      await addContact({ address: address.trim(), name: name.trim() || address.trim(), fingerprint: identity.fingerprint });
      close();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add contact');
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageShell
      embedded={embedded}
      title="Contacts"
      count={`${contacts.length} ${contacts.length === 1 ? 'person' : 'people'}`}
      actions={
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <div style={{ width: 240 }}>
            <Input value={q} onChange={e => setQ(e.target.value)} leadingIcon={<Icon name="search" size={16} />} placeholder="Search contacts" aria-label="Search contacts" />
          </div>
          <Button leftIcon={<Icon name="plus" size={16} />} onClick={() => setAdding(true)}>Add contact</Button>
        </div>
      }
    >
      <div style={{ padding: 'var(--space-6)' }}>
        {filtered.length === 0 ? (
          <div style={{ padding: 'var(--space-16) var(--space-4)', textAlign: 'center', color: 'var(--text-muted)' }}>
            <Icon name="users" size={28} style={{ color: 'var(--text-subtle)', margin: '0 auto' }} />
            <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-base)' }}>
              {q ? 'No contacts match your search.' : 'No contacts yet. Add someone to start an encrypted thread.'}
            </p>

          </div>
        ) : (
          <div style={{ maxWidth: 980, margin: '0 auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 'var(--space-3)' }}>
            {filtered.map(c => {
              // Every contact is an allowlist entry; provenance defaults to the
              // weakest tier (user_approved) when it was added before this feature.
              const rec = contactByAddress(c.address);
              const pv = provenanceView(rec?.provenance ?? 'user_approved');
              return (
              <div key={c.address} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-4)', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)' }}>
                <KindIcon kind={contactKind(rec)} size={16} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.name}</div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.address}</div>
                  {c.fingerprint && (
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-subtle)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{c.fingerprint}</div>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <Badge variant={pv.variant} dot>{pv.label}</Badge>
                  <IconButton size="sm" aria-label={`Remove ${c.name}`} onClick={() => void removeContact(c.address)}><Icon name="trash" size={16} /></IconButton>
                </div>
              </div>
              );
            })}
          </div>
        )}
      </div>

      <Dialog
        open={adding}
        onClose={close}
        title="Add contact"
        footer={
          <>
            <Button variant="secondary" onClick={close}>Cancel</Button>
            <Button onClick={handleAdd} disabled={!canSave || loading}>{loading ? 'Adding…' : 'Add contact'}</Button>
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Input
            {...emailInputProps}
            label="Email address"
            value={address}
            onChange={e => setAddress(e.target.value)}
            placeholder={`name@${DEFAULT_DOMAIN}`}
            required
            autoFocus
            error={error || undefined}
          />
          <Input
            label="Name (optional)"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Bob Vos"
          />
        </div>
      </Dialog>
    </PageShell>
  );
}
