import React from 'react';
import './Tag.css';

const X = (): React.ReactElement => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="square">
    <path d="M5 5l14 14M19 5L5 19" />
  </svg>
);

export interface TagProps extends Omit<React.HTMLAttributes<HTMLSpanElement>, 'color'> {
  /** Optional leading color swatch (folder/label color). */
  color?: string | null;
  /** When provided, renders a remove (×) button calling this handler. */
  onRemove?: ((e: React.MouseEvent) => void) | null;
}

/**
 * Removable label / category chip. Optional color swatch (folder labels),
 * optional remove button (recipient chips, filters).
 */
export function Tag({
  color = null,
  onRemove = null,
  className = '',
  children,
  ...rest
}: TagProps): React.ReactElement {
  const cls = ['dmcn-tag', className].filter(Boolean).join(' ');
  return (
    <span className={cls} {...rest}>
      {color && <span className="dmcn-tag__swatch" style={{ background: color }} />}
      {children}
      {onRemove && (
        <button type="button" className="dmcn-tag__remove" aria-label="Remove" onClick={onRemove}>
          <X />
        </button>
      )}
    </span>
  );
}
