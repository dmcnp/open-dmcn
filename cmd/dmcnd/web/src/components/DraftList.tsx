import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useDrafts } from '../lib/hooks/useDrafts';
import { useContacts } from '../lib/hooks/useContacts';
import { useIsMobile } from '../lib/useIsMobile';
import { formatWhen } from '../lib/format';
import type { MailOutletContext } from './AppLayout';
import { IconButton } from '../ds';
import { Icon } from './Icon';
import { ConfirmTrashButton } from './ConfirmTrashButton';

// The Drafts folder: messages started and not sent, newest first. A row opens the draft in the
// composer; deleting one (a second click on the red trash confirms it) removes it from every device. The rail shows this view only while there
// are drafts (AppLayout), so its empty state is only seen for the moment after the last one goes.
// Search leaves drafts out: they are not mail, and the search box's results are a view of their own.

export function DraftList() {
  const { drafts, store, refreshDrafts } = useDrafts();
  const { nameFor } = useContacts();
  const { openDraft, openDraftId, openCompose } = useOutletContext<MailOutletContext>();
  const isMobile = useIsMobile();
  const [hovered, setHovered] = useState<string | null>(null);
  // The row whose trash is waiting for its confirming click: it stays visible after the pointer leaves.
  const [armed, setArmed] = useState<string | null>(null);

  const rows = drafts;

  const remove = async (id: string) => {
    try {
      await store?.delete(id);
    } catch (err) {
      console.warn('Draft could not be deleted:', err);
    }
    void refreshDrafts();
  };

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      <div style={{
        padding: 'var(--space-3) var(--space-4)', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)',
      }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
          <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, letterSpacing: 'var(--tracking-tight)', color: 'var(--text-strong)' }}>
            Drafts
          </span>
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {rows.length} {rows.length === 1 ? 'draft' : 'drafts'}
          </span>
        </div>
        <IconButton size="sm" aria-label="Refresh" onClick={() => { void refreshDrafts(); }}><Icon name="refresh" size={16} /></IconButton>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', background: 'var(--surface-page)' }}>
        {rows.length === 0 ? (
          <div style={{ padding: 'var(--space-16) var(--space-4)', textAlign: 'center', color: 'var(--text-muted)' }}>
            <Icon name="file-pen" size={28} style={{ color: 'var(--text-subtle)', margin: '0 auto' }} />
            <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-base)' }}>
              No drafts.
            </p>
          </div>
        ) : rows.map(d => {
          const recipients = [...d.to, ...d.cc, ...d.bcc];
          const who = recipients.length ? `To: ${recipients.map(nameFor).join(', ')}` : '(no recipients)';
          const isOpen = d.id === openDraftId;
          const showActions = isMobile || hovered === d.id || armed === d.id;
          return (
            <div
              key={d.id}
              data-draft-row
              onClick={() => openDraft(d.id)}
              onMouseEnter={() => setHovered(d.id)}
              onMouseLeave={() => setHovered(h => (h === d.id ? null : h))}
              style={{
                display: 'flex', alignItems: isMobile ? 'flex-start' : 'center', gap: 'var(--space-3)', cursor: 'pointer',
                padding: isMobile ? 'var(--space-3) var(--space-4)' : 'var(--density-row) var(--space-4)',
                background: hovered === d.id ? 'var(--surface-hover)' : 'var(--surface-card)',
                borderBottom: '1px solid var(--border-subtle)',
                borderLeft: `2px solid ${isOpen ? 'var(--brand)' : 'transparent'}`,
              }}
            >
              {isMobile ? (
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
                    <span title={recipients.join(', ')} style={{ flex: 1, minWidth: 0, fontSize: 'var(--text-md)', color: 'var(--text-strong)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{who}</span>
                    {d.attachmentCount > 0 && <Icon name="paperclip" size={13} style={{ color: 'var(--text-muted)', flex: 'none' }} />}
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', flex: 'none' }}>{formatWhen(Math.floor(d.updatedAt / 1000))}</span>
                  </div>
                  <div style={{ marginTop: 2, fontSize: 'var(--text-md)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.subject || '(no subject)'}</div>
                  {d.snippet && <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{d.snippet}</div>}
                </div>
              ) : (
                <>
                  <span title={recipients.join(', ')} style={{ width: 220, flex: 'none', fontSize: 'var(--text-md)', color: 'var(--text-strong)', fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{who}</span>
                  <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span style={{ fontSize: 'var(--text-md)', color: 'var(--text-strong)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', ...(d.snippet ? { flex: 'none', maxWidth: '45%' } : { flex: '0 1 auto', minWidth: 0 }) }}>
                      {d.subject || '(no subject)'}
                    </span>
                    {d.snippet && (
                      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
                        &mdash; {d.snippet}
                      </span>
                    )}
                  </div>
                  {d.attachmentCount > 0 && <Icon name="paperclip" size={14} style={{ color: 'var(--text-muted)', flex: 'none' }} />}
                  <span style={{ flex: 'none', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatWhen(Math.floor(d.updatedAt / 1000))}</span>
                </>
              )}
              {/* Not for the draft the composer has open: it would only be saved straight back. */}
              <div style={{ flex: 'none', visibility: showActions && !isOpen ? 'visible' : 'hidden' }}>
                <ConfirmTrashButton
                  size="sm"
                  aria-label="Delete draft"
                  disabled={isOpen}
                  onConfirm={() => { void remove(d.id); }}
                  onArmedChange={on => setArmed(a => (on ? d.id : a === d.id ? null : a))}
                />
              </div>
            </div>
          );
        })}
      </div>

      {isMobile && (
        <button aria-label="Compose" onClick={() => openCompose(null)} style={{
          position: 'absolute', right: 'calc(var(--space-5) + env(safe-area-inset-right))',
          bottom: 'calc(var(--space-5) + env(safe-area-inset-bottom))', width: 56, height: 56,
          border: 'none', background: 'var(--brand)', color: 'var(--text-onbrand)', cursor: 'pointer',
          boxShadow: 'var(--shadow-md)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 35, borderRadius: 'var(--radius-md)',
        }}>
          <Icon name="pencil" size={22} />
        </button>
      )}
    </div>
  );
}
