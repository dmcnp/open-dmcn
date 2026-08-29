import type { ReactNode } from 'react';
import { Icon } from './Icon';
import { readTheme } from '../lib/theme';
import { deployment } from '@deployment';

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

/**
 * Authentication layout, shared by sign-in, register, import and device pairing so every
 * pre-auth screen matches. The form is always the left column; whether anything sits beside
 * it, and what name appears above it, are the deployment's to say (see lib/deployment.ts).
 */
export function AuthShell({ title, subtitle, children, note = deployment.branding.note, footer }: AuthShellProps) {
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
          {deployment.branding.mark}
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

      {/* Beside the form: the deployment's own panel, when it has one. Hidden on narrow
          viewports by .dmcn-auth-brand in tokens.css, where the form takes the screen. */}
      {deployment.branding.authPanel && (
        <div className="dmcn-auth-brand" style={{
          flex: '1 1 0', display: 'flex', flexDirection: 'column', justifyContent: 'center',
          padding: 'var(--space-20)',
        }}>
          {deployment.branding.authPanel}
        </div>
      )}

    </div>
  );
}
