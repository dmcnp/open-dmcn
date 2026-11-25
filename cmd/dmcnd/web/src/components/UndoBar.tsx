import { useEffect, useRef, useState } from 'react';
import { Button, IconButton } from '../ds';
import { Icon } from './Icon';
import type { UndoNotice } from '../lib/hooks/useUndo';

// The bar useUndo shows: what just happened, Undo, and a close button. It sits at the bottom of
// the window, clear of the phone's home indicator and to the left of the Compose button, and it is
// a status region, so a screen reader hears "Moved to Deleted" without the focus moving.
//
// The timer pauses while the pointer is on the bar or focus is in it: reaching for Undo must not
// race the bar going away.
export function UndoBar({ notice, onUndo, onDismiss, timeoutMs }: {
  notice: UndoNotice;
  onUndo: (n: UndoNotice) => void;
  onDismiss: (id: number) => void;
  timeoutMs: number;
}) {
  const [held, setHeld] = useState(false);
  const left = useRef(timeoutMs);
  const startedAt = useRef(0);

  useEffect(() => {
    if (held) return;
    startedAt.current = Date.now();
    const t = window.setTimeout(() => onDismiss(notice.id), left.current);
    return () => {
      window.clearTimeout(t);
      left.current = Math.max(1500, left.current - (Date.now() - startedAt.current));
    };
  }, [held, notice.id, onDismiss]);

  return (
    <div
      role="status"
      onPointerEnter={() => setHeld(true)}
      onPointerLeave={() => setHeld(false)}
      onFocus={() => setHeld(true)}
      onBlur={() => setHeld(false)}
      style={{
        position: 'fixed', zIndex: 60,
        left: 'calc(var(--space-4) + env(safe-area-inset-left))',
        // Clear of the floating Compose button on the phone (56px + its margin).
        right: 'calc(var(--space-4) + 72px + env(safe-area-inset-right))',
        bottom: 'calc(var(--space-5) + env(safe-area-inset-bottom))',
        maxWidth: 440, margin: '0 auto',
        display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
        padding: 'var(--space-2) var(--space-2) var(--space-2) var(--space-4)',
        background: 'var(--surface-raised)', color: 'var(--text-strong)',
        border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', boxShadow: 'var(--shadow-lg)',
        fontSize: 'var(--text-md)',
      }}
    >
      <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{notice.text}</span>
      {notice.undo && <Button variant="ghost" size="sm" leftIcon={<Icon name="undo" size={16} />} onClick={() => onUndo(notice)}>Undo</Button>}
      <IconButton size="sm" aria-label="Close" onClick={() => onDismiss(notice.id)}><Icon name="x" size={15} /></IconButton>
    </div>
  );
}
