import { useId } from 'react';
import './EmailAddressField.css';

// EmailAddressField is a single unified email-address control: a local-part input, an
// inline "@", and a domain chooser — a <select> when the deploy serves multiple domains
// (env.DOMAINS), or a static suffix when there's only one. Ported from the Claude Design
// "Sign in" mock (SignIn.dc.html → .dmcn-emailfield). The caller owns the local/domain
// state and composes `local@domain`; this component is presentation only.

export interface EmailAddressFieldProps {
  /** Field label rendered above the control. */
  label: string;
  /** Local-part value (before the "@") and its setter. */
  localPart: string;
  onLocalChange: (value: string) => void;
  /** Currently selected domain (after the "@") and its setter. */
  domain: string;
  onDomainChange: (value: string) => void;
  /** Domains offered. One → static suffix; more → a picker. */
  domains: string[];
  id?: string;
  required?: boolean;
  autoFocus?: boolean;
  /** Local-part placeholder. @default "you" */
  placeholder?: string;
}

export function EmailAddressField({
  label, localPart, onLocalChange, domain, onDomainChange, domains,
  id, required = false, autoFocus = false, placeholder = 'you',
}: EmailAddressFieldProps) {
  const rid = useId();
  const inputId = id ?? `email-local-${rid}`;
  // Three modes by how many domains the deploy offers: several ⇒ a dropdown, one
  // ⇒ a fixed suffix, none ⇒ let the user type the domain (an unconfigured
  // instance forces no default — the account being paired/imported may live on
  // any domain).
  const mode: 'picker' | 'fixed' | 'free' = domains.length > 1 ? 'picker' : domains.length === 1 ? 'fixed' : 'free';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
      <label className="dmcn-emailfield__label" htmlFor={inputId}>
        {label}{required && <span className="dmcn-emailfield__req">*</span>}
      </label>
      <div className="dmcn-emailfield">
        <input
          id={inputId}
          className="dmcn-emailfield__local"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          placeholder={placeholder}
          value={localPart}
          // The domain is chosen separately, so an "@" in the local part is always a
          // mistake — strip it rather than produce an invalid two-"@" address.
          onChange={e => onLocalChange(e.target.value.replace(/@/g, ''))}
          autoFocus={autoFocus}
          required={required}
        />
        <span className="dmcn-emailfield__at">@</span>
        {mode === 'picker' ? (
          <span className="dmcn-emailfield__domain-wrap">
            <select
              className="dmcn-emailfield__domain"
              aria-label="Domain"
              value={domain}
              onChange={e => onDomainChange(e.target.value)}
            >
              {domains.map(d => <option key={d} value={d}>{d}</option>)}
            </select>
            <svg className="dmcn-emailfield__caret" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m6 9 6 6 6-6" /></svg>
          </span>
        ) : mode === 'fixed' ? (
          <span className="dmcn-emailfield__domain-static">{domain}</span>
        ) : (
          <input
            className="dmcn-emailfield__domain-input"
            type="text"
            aria-label="Domain"
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            placeholder="yourdomain.com"
            value={domain}
            // Strip a stray "@" and lowercase — the domain is the part after the "@".
            onChange={e => onDomainChange(e.target.value.replace(/@/g, '').toLowerCase())}
            required={required}
          />
        )}
      </div>
    </div>
  );
}
