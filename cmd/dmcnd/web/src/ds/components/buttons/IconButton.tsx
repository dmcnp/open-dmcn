import React from 'react';
import './IconButton.css';

export interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** @default "ghost" */
  variant?: 'ghost' | 'solid' | 'outline';
  /** @default "md" */
  size?: 'sm' | 'md' | 'lg';
  /** Sticky selected state (e.g. active toolbar tool). @default false */
  active?: boolean;
}

/**
 * Square icon-only button. Use for toolbar actions, archive/delete,
 * sidebar toggles. Always pass an aria-label.
 */
export function IconButton({
  variant = 'ghost',
  size = 'md',
  active = false,
  type = 'button',
  className = '',
  children,
  ...rest
}: IconButtonProps): React.ReactElement {
  const cls = [
    'dmcn-iconbtn',
    `dmcn-iconbtn--${size}`,
    variant === 'solid' ? 'dmcn-iconbtn--solid' : '',
    variant === 'outline' ? 'dmcn-iconbtn--outline' : '',
    active ? 'dmcn-iconbtn--active' : '',
    className,
  ].filter(Boolean).join(' ');
  return (
    <button type={type} className={cls} {...rest}>
      {children}
    </button>
  );
}
