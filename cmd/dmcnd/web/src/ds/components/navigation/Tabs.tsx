import React from 'react';
import './Tabs.css';

export interface TabItem {
  value: string;
  label: React.ReactNode;
  icon?: React.ReactNode;
  /** Optional count pill (e.g. unread per category). */
  count?: number;
}

/** Props for the underline tab bar. */
export interface TabsProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'onChange'> {
  items: TabItem[];
  /** Currently selected tab value (controlled). */
  value: string;
  onChange?: (value: string) => void;
}

/**
 * Underline tab bar. Controlled via `value` / `onChange`.
 * items: [{ value, label, icon?, count? }]
 */
export function Tabs({
  items = [],
  value,
  onChange,
  className = '',
  ...rest
}: TabsProps): React.ReactElement {
  const cls = ['dmcn-tabs', className].filter(Boolean).join(' ');
  return (
    <div className={cls} role="tablist" {...rest}>
      {items.map((it) => {
        const active = it.value === value;
        return (
          <button
            key={it.value}
            role="tab"
            aria-selected={active}
            className={'dmcn-tab' + (active ? ' dmcn-tab--active' : '')}
            onClick={() => onChange && onChange(it.value)}
          >
            {it.icon}
            {it.label}
            {it.count != null && <span className="dmcn-tab__count">{it.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
