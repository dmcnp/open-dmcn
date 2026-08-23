import type { ReactNode } from 'react';
import { Icon } from './Icon';
import { readTheme } from '../lib/theme';
import { DEFAULT_DOMAIN } from '../lib/config';

export interface AuthShellProps {
  /** Heading above the form (e.g. "Welcome back"). */
  title: string;
  /** Sub-heading line under the title. */
  subtitle: string;
  /** The form / body content. */
  children: ReactNode;
  /** Reassurance line under the body (shield icon). Defaults to the standard line. */
  note?: ReactNode;
  /** Footer node (links). */
  footer?: ReactNode;
}

// No "we" here: the reference client has no provider behind it, and on a self-hosted
// daemon the operator may well be the reader themselves. State the property that is
// actually true of the software — keys stay on the device — and claim nothing about who
// is running the server.
const DEFAULT_NOTE = 'Your keys are generated and kept on this device. Mail is decrypted here, never on the server.';

/**
 * Single-panel authentication layout, shared by sign-in, register, import and device
 * pairing so every pre-auth screen matches.
 *
 * Deliberately unbranded. This client ships with no product identity: it is the webmail
 * the daemon serves, and the only name worth showing is the DEPLOYMENT's own domain —
 * whoever runs it. It carried a wordmark and a marketing panel ("Email that only you can
 * read", three feature columns) inherited from the hosted product; both are gone. A
 * reference implementation should not sell anything, and a self-hoster should not have to
 * strip someone else's brand out of their own mail client.
 */
export function AuthShell({ title, subtitle, children, note = DEFAULT_NOTE, footer }: AuthShellProps) {
  return (
    <div
      data-theme={readTheme()}
      style={{
        minHeight: '100dvh', display: 'flex', background: 'var(--surface-page)',
        color: 'var(--text-body)', fontFamily: 'var(--font-sans)', WebkitFontSmoothing: 'antialiased',
      }}
    >
      {/* Left: form (safe-area padding so it clears the status bar / home indicator in
          standalone PWA). On narrow viewports the form top-aligns with tighter padding
          — see .dmcn-auth-left in tokens.css. */}
      <div className="dmcn-auth-left" style={{
        flex: '1 1 0', display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: 'calc(var(--space-8) + env(safe-area-inset-top)) calc(var(--space-8) + env(safe-area-inset-right)) calc(var(--space-8) + env(safe-area-inset-bottom)) calc(var(--space-8) + env(safe-area-inset-left))',
      }}>
        <div style={{ width: '100%', maxWidth: 430 }}>
          {DEFAULT_DOMAIN && (
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)' }}>
              <Icon name="mail" size={20} />
              <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-strong)' }}>{DEFAULT_DOMAIN}</span>
            </div>
          )}
          <h1 style={{ margin: 'var(--space-6) 0 var(--space-1)', fontSize: 'var(--text-2xl)', fontWeight: 600, letterSpacing: 'var(--tracking-tight)', color: 'var(--text-strong)' }}>{title}</h1>
          <p style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--text-muted)' }}>{subtitle}</p>

          <div style={{ marginTop: 'var(--space-6)' }}>{children}</div>

          {note && (
            <div style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', lineHeight: 1.45 }}>
              <Icon name="shield-check" size={15} style={{ color: 'var(--brand)', flex: 'none', marginTop: 1 }} />
              <span>{note}</span>
            </div>
          )}
          {footer && <div style={{ marginTop: 'var(--space-6)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{footer}</div>}
        </div>
      </div>

    </div>
  );
}
