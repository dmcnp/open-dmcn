import { useRef, useState, type ReactNode } from 'react';
import { IconButton } from '../ds';
import { Icon } from './Icon';
import { moved, movedTo } from '../lib/filing';

// ReorderList puts a list of folders or labels in the owner's order. With a pointer, each row
// has up and down arrows: plain buttons, which a keyboard and a screen reader can use as they are.
// On a phone, each row has a handle to press and drag instead, since the arrows are small targets
// for a thumb. Either way the new order is handed to onReorder once, when the move is done.
//
// While dragging, the held row follows the finger and the rows it passes slide out of its way;
// letting go puts it where the gap is. Rows are assumed to share one height, which holds here.

export interface ReorderItem {
  id: string;
  /** What the row shows, between the handle (or arrows) and the row's own buttons. */
  content: ReactNode;
  /** Its name, for the buttons' accessible labels. */
  name: string;
}

export function ReorderList({ items, onReorder, drag, disabled = false, kind }: {
  items: ReorderItem[];
  onReorder: (ids: string[]) => void;
  /** Drag handles (the phone) rather than arrows. */
  drag: boolean;
  disabled?: boolean;
  /** "folder" or "label", for the labels. */
  kind: string;
}) {
  const ids = items.map(i => i.id);
  const [held, setHeld] = useState<{ index: number; dy: number; rowH: number } | null>(null);
  const start = useRef({ y: 0, index: 0, rowH: 0 });

  const target = held ? Math.max(0, Math.min(items.length - 1, held.index + Math.round(held.dy / held.rowH))) : -1;

  const onDown = (index: number) => (e: React.PointerEvent<HTMLSpanElement>) => {
    if (disabled) return;
    const row = (e.currentTarget.closest('[data-reorder-row]') as HTMLElement | null);
    const rowH = row?.offsetHeight || 44;
    start.current = { y: e.clientY, index, rowH };
    try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    setHeld({ index, dy: 0, rowH });
  };
  const onMove = (e: React.PointerEvent) => {
    if (!held) return;
    setHeld({ ...held, dy: e.clientY - start.current.y });
  };
  const onUp = () => {
    if (!held) return;
    const to = target;
    setHeld(null);
    if (to !== held.index) onReorder(movedTo(ids, held.index, to));
  };

  return (
    <div role="list" style={{ position: 'relative' }}>
      {items.map((item, index) => {
        // How far this row moves: the held one follows the finger; the ones between where it was
        // and where it would land shift one row the other way.
        let shift = 0;
        if (held) {
          if (index === held.index) shift = held.dy;
          else if (held.index < target && index > held.index && index <= target) shift = -held.rowH;
          else if (held.index > target && index < held.index && index >= target) shift = held.rowH;
        }
        const isHeld = held?.index === index;
        return (
          <div
            key={item.id}
            role="listitem"
            data-reorder-row
            style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) 0',
              transform: shift ? `translateY(${shift}px)` : undefined,
              transition: isHeld ? 'none' : 'transform var(--dur-fast) var(--ease-out)',
              position: 'relative', zIndex: isHeld ? 1 : undefined,
              background: isHeld ? 'var(--surface-card)' : undefined,
              boxShadow: isHeld ? 'var(--shadow-md)' : undefined,
              borderRadius: isHeld ? 'var(--radius-sm)' : undefined,
            }}
          >
            {drag ? (
              <span
                aria-hidden="true"
                onPointerDown={onDown(index)}
                onPointerMove={onMove}
                onPointerUp={onUp}
                onPointerCancel={() => setHeld(null)}
                style={{
                  flex: 'none', width: 32, height: 32, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--text-muted)', cursor: disabled ? 'default' : 'grab', touchAction: 'none',
                }}
              >
                <Icon name="grip" size={18} />
              </span>
            ) : (
              <span style={{ flex: 'none', display: 'inline-flex', flexDirection: 'column' }}>
                <IconButton size="sm" aria-label={`Move ${kind} ${item.name} up`} disabled={disabled || index === 0}
                  onClick={() => onReorder(moved(ids, index, -1))} style={{ height: 18 }}>
                  <Icon name="chevron-up" size={14} />
                </IconButton>
                <IconButton size="sm" aria-label={`Move ${kind} ${item.name} down`} disabled={disabled || index === items.length - 1}
                  onClick={() => onReorder(moved(ids, index, 1))} style={{ height: 18 }}>
                  <Icon name="chevron-down" size={14} />
                </IconButton>
              </span>
            )}
            {item.content}
          </div>
        );
      })}
    </div>
  );
}
