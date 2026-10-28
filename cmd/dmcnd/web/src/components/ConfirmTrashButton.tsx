import { useEffect, useId, useRef, useState } from 'react';
import { IconButton, type IconButtonProps } from '../ds';
import { Icon } from './Icon';
import './ConfirmTrashButton.css';

// A trash button that asks once, in place. The first click turns it red and points a note at it;
// a second click on it confirms. A press anywhere else, or focus leaving it, puts it back; that
// press then does whatever it would have done. Used where something that cannot be undone is
// thrown away from a list or the composer (a draft, a contact), without stopping anyone with a
// dialog.

export interface ConfirmTrashButtonProps extends Omit<IconButtonProps, 'onClick' | 'children'> {
  'aria-label': string;
  onConfirm: () => void;
  /** Told when the button turns red and when it goes back, so a row can keep it visible meanwhile. */
  onArmedChange?: (armed: boolean) => void;
}

export function ConfirmTrashButton({ onConfirm, onArmedChange, className = '', ...rest }: ConfirmTrashButtonProps) {
  const [armed, setArmed] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);
  const tipId = useId();
  const notify = useRef(onArmedChange);
  notify.current = onArmedChange;

  const set = (next: boolean) => {
    setArmed(next);
    notify.current?.(next);
  };

  useEffect(() => {
    if (!armed) return;
    // Capture phase, so a press elsewhere that stops its own propagation still counts.
    const onDown = (e: PointerEvent) => {
      if (wrapRef.current?.contains(e.target as Node)) return;
      setArmed(false);
      notify.current?.(false);
    };
    document.addEventListener('pointerdown', onDown, true);
    return () => document.removeEventListener('pointerdown', onDown, true);
  }, [armed]);

  return (
    <span ref={wrapRef} className="confirm-trash">
      <IconButton
        {...rest}
        className={`${className}${armed ? ' confirm-trash__btn--armed' : ''}`}
        aria-describedby={armed ? tipId : undefined}
        onClick={e => {
          e.stopPropagation();
          if (armed) { set(false); onConfirm(); } else set(true);
        }}
        onBlur={() => { if (armed) set(false); }}
      >
        <Icon name="trash" size={rest.size === 'sm' ? 16 : undefined} />
      </IconButton>
      {armed && (
        <span id={tipId} role="tooltip" aria-live="polite" className="confirm-trash__tip">
          Click again to confirm
        </span>
      )}
    </span>
  );
}
