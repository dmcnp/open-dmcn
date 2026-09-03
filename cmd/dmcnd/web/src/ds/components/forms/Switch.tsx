import React from 'react';
import './Switch.css';

export interface SwitchProps {
  /** On/off state (controlled). @default false */
  checked?: boolean;
  /** Fires with the next boolean value and the change event. */
  onChange?: (checked: boolean, event: React.ChangeEvent<HTMLInputElement>) => void;
  /** @default false */
  disabled?: boolean;
  /** Inline label text. */
  label?: React.ReactNode;
  id?: string;
}

/**
 * On/off toggle. One of the few intentionally-rounded elements in DMCN.
 */
export function Switch({
  checked = false,
  onChange,
  disabled = false,
  label,
  id,
  ...rest
}: SwitchProps): React.ReactElement {
  const sid =
    id || (typeof label === 'string' ? 'sw-' + label.replace(/\s+/g, '-').toLowerCase() : undefined);
  return (
    <label
      className={'dmcn-switch' + (checked ? ' dmcn-switch--on' : '')}
      aria-disabled={disabled}
      htmlFor={sid}
    >
      <input
        id={sid}
        type="checkbox"
        role="switch"
        className="dmcn-switch__native"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange && onChange(e.target.checked, e)}
        {...rest}
      />
      <span className="dmcn-switch__track">
        <span className="dmcn-switch__thumb" />
      </span>
      {label && <span className="dmcn-switch__label">{label}</span>}
    </label>
  );
}
