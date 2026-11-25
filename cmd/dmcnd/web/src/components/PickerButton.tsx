import { useState, type CSSProperties, type ReactNode } from 'react';
import { Icon } from './Icon';

// NativePicker puts a real <select> over whatever it wraps, invisible: the platform's own list,
// keyboard and screen-reader behaviour (and a phone's own picker sheet) come with it, and nothing
// has to be rebuilt to look like a menu. The select always rests on `value`, so choosing the same
// thing twice still reports it, and a choice that hands over to something else ("New folder…")
// leaves nothing selected behind it.
export function NativePicker({ label, value, onChange, options, children, style, onFocusChange }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** The <option>s. */
  options: ReactNode;
  /** What shows. */
  children: ReactNode;
  style?: CSSProperties;
  /** Focus moving in or out: a row keeps its hover actions showing while one of them is open. */
  onFocusChange?: (focused: boolean) => void;
}) {
  const [focused, setFocused] = useState(false);
  const focus = (f: boolean) => { setFocused(f); onFocusChange?.(f); };
  return (
    <span title={label} style={{ position: 'relative', flex: 'none', display: 'inline-flex', boxShadow: focused ? 'var(--focus-ring)' : undefined, ...style }}>
      {children}
      <select
        aria-label={label}
        value={value}
        onFocus={() => focus(true)}
        onBlur={() => focus(false)}
        onClick={e => e.stopPropagation()}
        // Closing the list with Escape picks nothing, so onChange never runs: let go here too.
        onKeyDown={e => { if (e.key === 'Escape') e.currentTarget.blur(); }}
        onPointerDown={e => e.stopPropagation()}
        onChange={e => {
          const v = e.target.value;
          e.currentTarget.value = value;
          // Let go of the list once something is picked: a select keeps focus after a choice, which
          // would keep a row's hover actions showing until the next click elsewhere.
          e.currentTarget.blur();
          onChange(v);
        }}
        style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: 0, cursor: 'pointer', font: 'inherit', border: 0 }}
      >
        {options}
      </select>
    </span>
  );
}

// PickerButton is a toolbar icon that opens a native picker.
export function PickerButton({ icon, label, value, onChange, children, size = 36, onFocusChange }: {
  icon: 'tag' | 'folder';
  label: string;
  value: string;
  onChange: (value: string) => void;
  /** The <option>s. */
  children: ReactNode;
  size?: number;
  onFocusChange?: (focused: boolean) => void;
}) {
  return (
    <NativePicker label={label} value={value} onChange={onChange} options={children} onFocusChange={onFocusChange} style={{
      width: size, height: size, alignItems: 'center', justifyContent: 'center',
      borderRadius: 'var(--radius-sm)', color: 'var(--text-body)',
    }}>
      <Icon name={icon} size={size >= 36 ? 18 : 16} />
    </NativePicker>
  );
}

/** Option values the pickers share: a choice that is not an id. */
export const PICK_PROMPT = '__prompt';
export const PICK_INBOX = '__inbox';
export const PICK_NEW = '__new';
