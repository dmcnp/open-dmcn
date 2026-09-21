// The (i) next to a label whose one-line description cannot carry the whole answer.
//
// Settings is full of rows where the honest explanation is a paragraph — what a key fingerprint
// is for, what "best effort" means when a device is removed, why loading remote images tells the
// sender you read the message. Those paragraphs used to be either compressed into a sentence that
// lost the caveat, or left off the screen entirely. Neither is good enough on a product whose
// whole pitch is that you can check its claims.
//
// Tooltip already covers the one-liner. This is for the rest: a button that opens the Dialog the
// design system already has, so nothing new is invented and the explanation is reachable by
// keyboard, dismissable with Escape, and readable at phone width.

import { useState, type ReactNode } from 'react';
import { Dialog } from '../ds';
import { Icon } from './Icon';

export interface InfoHintProps {
  /** Dialog heading. Usually the row's own title, so the reader knows what they opened. */
  title: string;
  /** The explanation. A paragraph or several, not a sentence — a sentence belongs in `desc`. */
  children: ReactNode;
  /** Accessible name for the trigger; defaults to naming the title it explains. */
  label?: string;
}

export function InfoHint({ title, children, label }: InfoHintProps) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label={label ?? `What ${title} means`}
        style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: 22, height: 22, padding: 0, marginLeft: 6, verticalAlign: '-5px',
          border: 0, borderRadius: 'var(--radius-sm)', background: 'transparent',
          color: 'var(--text-subtle)', cursor: 'pointer',
        }}
      >
        <Icon name="info" size={15} />
      </button>
      <Dialog open={open} onClose={() => setOpen(false)} title={title}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)', fontSize: 'var(--text-sm)', lineHeight: 1.6, color: 'var(--text-body)' }}>
          {children}
        </div>
      </Dialog>
    </>
  );
}
