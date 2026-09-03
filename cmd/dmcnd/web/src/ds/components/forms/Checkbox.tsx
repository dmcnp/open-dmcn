import React from 'react';
import './Checkbox.css';

const Check = (): React.ReactElement => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="square" strokeLinejoin="miter">
    <path d="M4 12l5 5L20 6" />
  </svg>
);

export interface CheckboxProps {
  /** Checked state (controlled). @default false */
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
 * Square checkbox with label. Controlled via `checked` / `onChange`.
 */
export function Checkbox({
  checked = false,
  onChange,
  disabled = false,
  label,
  id,
  ...rest
}: CheckboxProps): React.ReactElement {
  const cid =
    id || (typeof label === 'string' ? 'cb-' + label.replace(/\s+/g, '-').toLowerCase() : undefined);
  return (
    <label
      className={'dmcn-check' + (checked ? ' dmcn-check--on' : '')}
      aria-disabled={disabled}
      htmlFor={cid}
    >
      <input
        id={cid}
        type="checkbox"
        className="dmcn-check__native"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange && onChange(e.target.checked, e)}
        {...rest}
      />
      <span className="dmcn-check__box">
        <Check />
      </span>
      {label && <span className="dmcn-check__label">{label}</span>}
    </label>
  );
}
