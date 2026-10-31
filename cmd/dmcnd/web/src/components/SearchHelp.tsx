// The (i) beside the mail search box: every search option on one card, each with an example.
//
// A box anchored to the button rather than a Dialog (InfoHint's way): this is a reference you
// glance at while typing, so it leaves the search box and the results in view. It closes on a
// second press, on Escape, and on any press outside it.
//
// The operators are the ones lib/search/query.ts reads; a change there belongs here too.

import { useEffect, useId, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { IconButton } from '../ds';
import { Icon } from './Icon';

const OPTIONS: { example: string; meaning: string }[] = [
  { example: 'invoice', meaning: 'Sender, recipients, subject, message text or attachment names. The start of a word is enough.' },
  { example: 'from:alice', meaning: 'Who sent it, by name or address.' },
  { example: 'to:bob', meaning: 'Who it went to, Cc included.' },
  { example: 'subject:report', meaning: 'Words in the subject.' },
  { example: 'has:attachment', meaning: 'Has an attachment.' },
  { example: 'filename:*.pdf', meaning: 'Attachment name. * stands for anything.' },
  { example: 'is:unread', meaning: 'Also is:read and is:starred.' },
  { example: 'label:work', meaning: 'Has this label.' },
  { example: 'in:archive', meaning: 'Where it is: inbox, archive, sent, deleted, or a folder name.' },
  { example: 'after:2026-01-31', meaning: 'Sent on or after that day. before: means sent before it.' },
  { example: '-from:alice', meaning: 'A minus in front leaves those out.' },
  { example: 'from:"Alice Smith"', meaning: 'Quotes keep a value with spaces together.' },
];

// The md IconButton is 38px wide and the card's right edge sits 4px past the button's, so the
// arrow's middle is 23px in from the card's right edge.
const CARD_RIGHT = -4;
const ARROW = 12;
const ARROW_RIGHT = 38 / 2 - CARD_RIGHT - ARROW / 2;

const card: CSSProperties = {
  position: 'absolute', top: 'calc(100% + 10px)', right: CARD_RIGHT, zIndex: 60,
  width: 380, maxWidth: 'calc(100vw - 16px)',
  background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)',
  boxShadow: 'var(--shadow-md)', color: 'var(--text-body)', textAlign: 'left',
};

export function SearchHelp() {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    const escape = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('pointerdown', away);
    document.addEventListener('keydown', escape);
    return () => {
      document.removeEventListener('pointerdown', away);
      document.removeEventListener('keydown', escape);
    };
  }, [open]);

  return (
    <span ref={wrap} style={{ position: 'relative', display: 'inline-flex', flex: 'none' }}>
      <IconButton aria-label="Search options" title="Search options" aria-expanded={open} aria-controls={id} active={open} onClick={() => setOpen(o => !o)}>
        <Icon name="info" />
      </IconButton>
      {open && (
        <div id={id} role="dialog" aria-label="Search options" style={card}>
          <span aria-hidden="true" style={{
            position: 'absolute', top: -ARROW / 2 - 1, right: ARROW_RIGHT, width: ARROW, height: ARROW,
            background: 'var(--surface-card)', borderLeft: '1px solid var(--border-default)', borderTop: '1px solid var(--border-default)',
            transform: 'rotate(45deg)',
          }} />
          {/* The scrolling box sits inside the card so the arrow, outside its bounds, is not clipped. */}
          <div style={{ maxHeight: 'calc(100dvh - 96px)', overflowY: 'auto', padding: 'var(--space-3) var(--space-4)' }}>
            <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)', marginBottom: 'var(--space-2)' }}>Search options</div>
            <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', columnGap: 'var(--space-3)', rowGap: 'var(--space-2)', margin: 0, fontSize: 'var(--text-sm)' }}>
              {OPTIONS.map(o => (
                <div key={o.example} style={{ display: 'contents' }}>
                  <dt style={{ margin: 0 }}>
                    <code style={{
                      fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-strong)', whiteSpace: 'nowrap',
                      background: 'var(--surface-sunken)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '1px 5px',
                    }}>{o.example}</code>
                  </dt>
                  <dd style={{ margin: 0, color: 'var(--text-muted)', lineHeight: 1.45 }}>{o.meaning}</dd>
                </div>
              ))}
            </dl>
            <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
              Combine as many as you like: a message has to match all of them. Searching happens on this device.
            </p>
          </div>
        </div>
      )}
    </span>
  );
}
