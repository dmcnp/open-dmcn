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
  const strip = React.useRef<HTMLDivElement>(null);

  // Keep the selected tab on screen. The strip scrolls once the labels outgrow it (a phone), so a
  // tab selected from elsewhere — or simply the one that was already active on arrival — can sit
  // past the edge with nothing to say it is there. Scrolling the container itself rather than
  // calling scrollIntoView, which is free to scroll the PAGE as well to satisfy the request.
  React.useEffect(() => {
    const el = strip.current;
    const tab = el?.querySelector<HTMLElement>('[aria-selected="true"]');
    if (!el || !tab) return;
    const centred = tab.offsetLeft - (el.clientWidth - tab.offsetWidth) / 2;
    // Instant, not smooth: this also runs on first paint, where an animated slide would be a
    // glitch rather than a transition, and a screenshot could catch it mid-flight.
    el.scrollTo({ left: Math.max(0, centred) });
  }, [value, items]);

  return (
    <div className={cls} role="tablist" ref={strip} {...rest}>
      {items.map((it) => {
        const active = it.value === value;
        // A tab can drop to its icon alone on a phone (see Tabs.css) only if it HAS an icon and a
        // plain-text label to move onto aria-label. Anything else — no icon, or a label built from
        // nodes — keeps its words, because hiding them would leave a button saying nothing.
        const labelText = typeof it.label === 'string' ? it.label : undefined;
        const compact = it.icon != null && labelText !== undefined;
        return (
          <button
            key={it.value}
            role="tab"
            aria-selected={active}
            // Carried on the button, not left to the text, because that text is display:none at
            // phone widths and a hidden label is no label at all to the accessibility tree.
            aria-label={compact ? labelText : undefined}
            className={'dmcn-tab' + (active ? ' dmcn-tab--active' : '') + (compact ? ' dmcn-tab--compact' : '')}
            onClick={() => onChange && onChange(it.value)}
          >
            {it.icon}
            <span className="dmcn-tab__label">{it.label}</span>
            {it.count != null && <span className="dmcn-tab__count">{it.count}</span>}
          </button>
        );
      })}
    </div>
  );
}
