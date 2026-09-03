import React from 'react';
import './Badge.css';

/** Props for the status / category badge. */
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** @default "neutral" */
  variant?: 'neutral' | 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'trust-contact' | 'trust-dmcn' | 'solid';
  /** Leading status dot. @default false */
  dot?: boolean;
  /** Leading icon element. */
  icon?: React.ReactNode;
}

/**
 * Compact status / category label. Use for "Encrypted", unread counts,
 * folder labels, message states.
 */
export function Badge({
  variant = 'neutral',
  dot = false,
  icon = null,
  className = '',
  children,
  ...rest
}: BadgeProps): React.ReactElement {
  const cls = ['dmcn-badge', `dmcn-badge--${variant}`, className].filter(Boolean).join(' ');
  return (
    <span className={cls} {...rest}>
      {dot && <span className="dmcn-badge__dot" />}
      {icon}
      {children}
    </span>
  );
}
