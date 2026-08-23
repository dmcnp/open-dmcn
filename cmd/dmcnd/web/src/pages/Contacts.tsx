import { useState } from 'react';
import { useContacts } from '../lib/hooks/useContacts';
import type { ContactRecord } from '../lib/api/contactStore';
import { lookupIdentity } from '../lib/api/client';
import { PageShell } from '../components/PageShell';
import { useIsMobile } from '../lib/useIsMobile';
import { DEFAULT_DOMAIN } from '../lib/config';
import { emailInputProps } from '../lib/emailInput';
import { Button, Dialog, IconButton, Input } from '../ds';
import { Icon } from '../components/Icon';
import { KindIcon } from '../components/KindIcon';
import { hasPinnedKey } from '../lib/trust/pinnedKey';
import { contactKind } from '../lib/trust/senderKind';

// The DMCN-vs-legacy distinction (see senderKind.ts) is what's worth a glance in
// this list; the allowlist provenance ("trusted sender") is not, since every row
// here is by definition allowlisted.

type Mode = { kind: 'add' } | { kind: 'edit'; address: string } | null;

export function Contacts() {
  const { contacts, contactByAddress, nameFor, addContact, updateContact, removeContact, pinAlerts } = useContacts();
  const isMobile = useIsMobile();
  const embedded = !isMobile;
  const [q, setQ] = useState('');
  const [mode, setMode] = useState<Mode>(null);
  const [address, setAddress] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  // Set when the directory has no record for the typed address: the save turns into
  // an explicit "add as a legacy email contact" rather than silently filing a typo'd
  // DMCN address as legacy.
  const [legacyPrompt, setLegacyPrompt] = useState(false);

  const filtered = contacts.filter(c => `${c.name} ${c.address}`.toLowerCase().includes(q.trim().toLowerCase()));

  const reset = () => { setAddress(''); setName(''); setError(''); setLegacyPrompt(false); };
  const close = () => { setMode(null); reset(); };
  const canSave = mode?.kind === 'edit' ? true : address.trim().length > 0;

  const openAdd = () => { reset(); setMode({ kind: 'add' }); };
  const openEdit = (rec: ContactRecord) => {
    reset();
    setAddress(rec.address);
    // Seed the field with the editable name only — a record whose name is just the
    // address (the reader's allowlist action seeds it that way) starts blank.
    const current = nameFor(rec.address);
    setName(current === rec.address ? '' : current);
    setMode({ kind: 'edit', address: rec.address });
  };

  const handleAdd = async () => {
    if (!canSave) return;
    setLoading(true);
    setError('');
    try {
      const addr = address.trim();
      // Contacts are keyed by address, so "adding" one that already exists is a
      // rename — route it through update() so the record keeps its trust provenance
      // and pinned keys instead of being overwritten with bare form fields.
      if (contactByAddress(addr)) {
        await updateContact(addr, { name: name.trim() || addr });
        close();
        return;
      }
      if (legacyPrompt) {
        // Confirmed legacy: no fingerprint to store — the address is all there is.
        await addContact({ address: addr, name: name.trim() || addr, fingerprint: '' });
        close();
        return;
      }
      try {
        const identity = await lookupIdentity(addr);
        await addContact({ address: addr, name: name.trim() || addr, fingerprint: identity.fingerprint });
        close();
      } catch {
        setLegacyPrompt(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add contact');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveEdit = async () => {
    if (mode?.kind !== 'edit') return;
    setLoading(true);
    setError('');
    try {
      // An empty name falls back to the address, matching how contacts added without
      // a name are stored.
      await updateContact(mode.address, { name: name.trim() || mode.address });
      close();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save contact');
    } finally {
      setLoading(false);
    }
  };

  const editing = mode?.kind === 'edit' ? contactByAddress(mode.address) : undefined;

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
          <Button leftIcon={<Icon name="plus" size={16} />} onClick={openAdd}>Add contact</Button>
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
          // One contact per full-width row: names and addresses get the whole column
          // instead of competing with a badge inside a narrow card.
          <div style={{ maxWidth: 880, margin: '0 auto', background: 'var(--surface-card)', border: '1px solid var(--border-subtle)' }}>
            {filtered.map((c, i) => {
              const rec = contactByAddress(c.address);
              const label = nameFor(c.address);
              const named = label !== c.address;
              const alert = pinAlerts.find(a => a.address.trim().toLowerCase() === c.address.trim().toLowerCase());
              return (
                <div
                  key={c.address}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                    padding: 'var(--space-3) var(--space-4)',
                    borderTop: i === 0 ? 'none' : '1px solid var(--border-subtle)',
                  }}
                >
                  <KindIcon kind={contactKind(rec)} size={16} />
                  {/* Whether this contact has key-change protection at all. A contact with no
                      pinned key is not "untrusted" — it just means a silent key swap would go
                      unnoticed for them, which is worth being able to see at a glance. Pinning
                      happens automatically the next time we resolve them (on read, or when they
                      are added as a compose recipient). */}
                  {!hasPinnedKey(rec) && (
                    <span
                      title="No key pinned yet — a key change for this contact would not be detected. Pins itself the next time you read a message from them or address one to them."
                      style={{ flex: 'none', display: 'inline-flex', alignItems: 'center', color: 'var(--text-subtle)' }}
                    >
                      <Icon name="shield-off" size={14} />
                    </span>
                  )}
                  {/* The synced copy of this contact's pin disagrees with the one held on this
                      device. This device's pin is the one in force either way — the flag exists
                      because the disagreement is itself the signal. It is not proof of anything:
                      a device that pinned while offline produces it too. But a contacts blob that
                      comes back missing a pin you took, or carrying a different one, is what a
                      rollback by the relay looks like, and it should not pass in silence. */}
                  {alert && (
                    <span
                      title={alert.anomaly === 'kv_missing'
                        ? 'The synced copy of your address book no longer carries the key you pinned for this contact. This device is still using the key it pinned, and has pushed it back. If you did not expect this, verify their key out of band.'
                        : 'The synced copy of your address book carries a different key for this contact than the one this device pinned. This device is still using the key it pinned. If they legitimately rotated, remove and re-add them to accept the new key.'}
                      style={{ flex: 'none', display: 'inline-flex', alignItems: 'center', color: 'var(--warning)' }}
                    >
                      <Icon name="alert-triangle" size={14} />
                    </span>
                  )}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {label}
                    </div>
                    {named && (
                      <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.address}</div>
                    )}
                  </div>
                  {!isMobile && c.fingerprint && (
                    <div
                      title={c.fingerprint}
                      style={{ flex: 'none', width: 200, fontSize: 'var(--text-xs)', color: 'var(--text-subtle)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                    >
                      {c.fingerprint}
                    </div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', flex: 'none' }}>
                    <IconButton size="sm" aria-label={`Edit ${label}`} onClick={() => rec && openEdit(rec)}><Icon name="pencil" size={16} /></IconButton>
                    <IconButton size="sm" aria-label={`Remove ${label}`} onClick={() => void removeContact(c.address)}><Icon name="trash" size={16} /></IconButton>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <Dialog
        open={mode !== null}
        onClose={close}
        title={mode?.kind === 'edit' ? 'Edit contact' : 'Add contact'}
        footer={
          <>
            <Button variant="secondary" onClick={close}>Cancel</Button>
            {mode?.kind === 'edit' ? (
              <Button onClick={handleSaveEdit} disabled={loading}>{loading ? 'Saving…' : 'Save'}</Button>
            ) : (
              <Button onClick={handleAdd} disabled={!canSave || loading}>
                {loading ? 'Adding…' : legacyPrompt ? 'Add as legacy contact' : 'Add contact'}
              </Button>
            )}
          </>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {mode?.kind === 'edit' ? (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <KindIcon kind={contactKind(editing)} size={16} />
                <span style={{ fontSize: 'var(--text-md)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mode.address}</span>
              </div>
              {editing?.fingerprint && (
                <div style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--text-subtle)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                  {editing.fingerprint}
                </div>
              )}
            </div>
          ) : (
            <Input
              {...emailInputProps}
              label="Email address"
              value={address}
              onChange={e => { setAddress(e.target.value); setLegacyPrompt(false); }}
              placeholder={`name@${DEFAULT_DOMAIN}`}
              required
              autoFocus
              error={error || undefined}
            />
          )}
          <Input
            label="Name"
            type="text"
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="Bob Vos"
            autoFocus={mode?.kind === 'edit'}
            error={mode?.kind === 'edit' ? error || undefined : undefined}
          />
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {legacyPrompt
              ? 'No DMCN identity is published for this address. Add it as a legacy email contact — mail to it is delivered over a bridge and cannot be end-to-end encrypted.'
              : 'The name you set here is what this app shows for this address everywhere — inbox, message headers and compose.'}
          </p>
        </div>
      </Dialog>
    </PageShell>
  );
}
