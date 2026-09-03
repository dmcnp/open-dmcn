import React from 'react';
import './Tooltip.css';

export interface TooltipProps {
  /** Tooltip text. */
  label: React.ReactNode;
  /** @default "top" */
  side?: 'top' | 'bottom' | 'left' | 'right';
  /** Single interactive child the tooltip describes. */
  children: React.ReactNode;
}

/**
 * Lightweight hover/focus tooltip. Wrap a single interactive child.
 */
export function Tooltip({ label, side = 'top', children }: TooltipProps): React.ReactElement {
  const [show, setShow] = React.useState(false);
  return (
    <span
      className="dmcn-tip-wrap"
      onMouseEnter={() => setShow(true)}
      onMouseLeave={() => setShow(false)}
      onFocus={() => setShow(true)}
      onBlur={() => setShow(false)}
    >
      {children}
      <span role="tooltip" className={`dmcn-tip dmcn-tip--${side}${show ? ' dmcn-tip--show' : ''}`}>
        {label}
      </span>
    </span>
  );
}
