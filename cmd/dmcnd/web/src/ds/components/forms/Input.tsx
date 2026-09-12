import React from 'react';
import './Input.css';

/** Props for the labelled text input. */
export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  /** Field label rendered above the input. */
  label?: string;
  /** Helper text below the field. */
  hint?: string;
  /** Error message; replaces hint and turns the field red. */
  error?: string;
  /** Show required asterisk. @default false */
  required?: boolean;
  /** Icon element shown inside the field, leading edge. Decorative: no pointer events. */
  leadingIcon?: React.ReactNode;
  /** Interactive control shown INSIDE the field on the trailing edge — a generate, clear or
   * reveal button. Unlike leadingIcon it stays clickable, and the field reserves room for it so
   * the value never runs underneath. */
  trailingAction?: React.ReactNode;
}

/**
 * Text input with optional label, leading icon, hint / error.
 */
export function Input({
  label,
  hint,
  error,
  required = false,
  leadingIcon = null,
  trailingAction = null,
  id,
  className = '',
  ...rest
}: InputProps): React.ReactElement {
  const inputId = id || (label ? 'in-' + label.replace(/\s+/g, '-').toLowerCase() : undefined);
  const inputCls = [
    'dmcn-input',
    leadingIcon ? 'dmcn-input--with-icon' : '',
    trailingAction ? 'dmcn-input--with-action' : '',
    error ? 'dmcn-input--invalid' : '',
    className,
  ].filter(Boolean).join(' ');
  return (
    <div className="dmcn-field">
      {label && (
        <label className="dmcn-field__label" htmlFor={inputId}>
          {label}
          {required && <span className="dmcn-field__req">*</span>}
        </label>
      )}
      <div className="dmcn-input-wrap">
        {leadingIcon && <span className="dmcn-input-wrap__icon">{leadingIcon}</span>}
        <input id={inputId} className={inputCls} aria-invalid={!!error} {...rest} />
        {trailingAction && <span className="dmcn-input-wrap__action">{trailingAction}</span>}
      </div>
      {(hint || error) && (
        <span className={'dmcn-field__hint' + (error ? ' dmcn-field__hint--error' : '')}>
          {error || hint}
        </span>
      )}
    </div>
  );
}

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
  required?: boolean;
}

/**
 * Multi-line text input. Shares Input styling; vertical resize only.
 */
export function Textarea({
  label,
  hint,
  error,
  required = false,
  id,
  className = '',
  ...rest
}: TextareaProps): React.ReactElement {
  const inputId = id || (label ? 'ta-' + label.replace(/\s+/g, '-').toLowerCase() : undefined);
  const cls = ['dmcn-input', 'dmcn-textarea', error ? 'dmcn-input--invalid' : '', className]
    .filter(Boolean)
    .join(' ');
  return (
    <div className="dmcn-field">
      {label && (
        <label className="dmcn-field__label" htmlFor={inputId}>
          {label}
          {required && <span className="dmcn-field__req">*</span>}
        </label>
      )}
      <textarea id={inputId} className={cls} aria-invalid={!!error} {...rest} />
      {(hint || error) && (
        <span className={'dmcn-field__hint' + (error ? ' dmcn-field__hint--error' : '')}>
          {error || hint}
        </span>
      )}
    </div>
  );
}
