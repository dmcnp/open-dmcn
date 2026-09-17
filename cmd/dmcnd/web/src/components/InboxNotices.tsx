// Where a request-shaped control message gets noticed.
//
// Device pairing, address countersign and anything later of that shape arrive as ordinary
// mail, are kept out of every folder by controlSubjects, and would otherwise be found only
// by someone who already knew to go looking for them — behind a rail row on the desktop and
// behind the drawer on a phone. They surface here instead: one row per kind at the top of
// the inbox, opening into whatever the deployment put behind it.
//
// One row per KIND, not per request, and worded by the shell (see InboxNotice). Anyone who
// knows an address can drop a request into its mailbox, so a row per request would hand a
// stranger a wall of them, and a row carrying the requester's own text would let a stranger
// write a sentence in the app's voice at the top of someone's inbox.

import { useState } from 'react';
import { deployment } from '@deployment';
import { useMessages } from '../lib/hooks/useMessages';
import { Dialog } from '../ds';
import { Icon } from './Icon';

export function InboxNotices() {
  const { messages } = useMessages();
  const [openSubject, setOpenSubject] = useState<string | null>(null);
  const notices = deployment.inboxNotices ?? [];

  // Counted off the preview subject alone — no body fetch, the same cheap count the rail
  // rows used. A request whose attachment turns out to be undecodable still counts here;
  // the dialog is what knows how to read them, and simply won't list that one.
  const countOf = (subject: string) => messages.filter(m => m.subject === subject).length;

  // Looked up among ALL notices, not just the raised ones: approving the last request drops
  // its count to zero, and the dialog must not be yanked away before its result is read.
  const open = notices.find(n => n.subject === openSubject);
  const View = open?.view;
  const close = () => setOpenSubject(null);

  return (
    <>
      {notices.map(n => {
        const count = countOf(n.subject);
        if (count === 0) return null;
        return (
          <button
            key={n.subject}
            type="button"
            onClick={() => setOpenSubject(n.subject)}
            // Full-bleed, on the list's own horizontal rhythm: this is the first row of the
            // inbox, not a card floating above it.
            style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-3)', boxSizing: 'border-box',
              width: '100%', padding: 'var(--space-3) var(--space-4)', textAlign: 'left', cursor: 'pointer',
              background: 'var(--brand-subtle)', color: 'var(--brand-text)',
              border: 'none', borderBottom: '1px solid var(--border-subtle)',
              font: 'inherit', fontSize: 'var(--text-sm)',
            }}
          >
            <Icon name={n.icon} size={16} style={{ color: 'var(--brand)', flex: 'none' }} />
            <span style={{ flex: 1, minWidth: 0 }}>{n.summary(count)}</span>
            <Icon name="chevron-right" size={16} style={{ flex: 'none' }} />
          </button>
        );
      })}

      <Dialog open={!!open} title={open?.title} onClose={close} maxWidth={720}>
        {View && <View onClose={close} />}
      </Dialog>
    </>
  );
}
