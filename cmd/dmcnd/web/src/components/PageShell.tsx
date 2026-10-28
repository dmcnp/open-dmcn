import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { IconButton } from '../ds';
import { Icon } from './Icon';
import { readTheme, readDensity } from '../lib/theme';

export interface PageShellProps {
  /** Header title. */
  title: string;
  /** Optional count / subtitle shown next to the title. */
  count?: string;
  /** Optional actions rendered on the right of the header. */
  actions?: ReactNode;
  /**
   * Standalone only: shown in place of the back button and title, across the header up to the
   * actions — a search field that has opened over it. The actions stay where they were, so a
   * press on one that also closes this (by blurring the field) still lands.
   */
  headerContent?: ReactNode;
  /** Override the persisted theme (e.g. Settings' live appearance preview). Standalone only. */
  theme?: 'light' | 'dark';
  /** Override the persisted density. Standalone only. */
  density?: 'compact' | 'comfortable';
  /**
   * Embedded mode renders inside the app shell's main column (desktop): no themed
   * root, no back button — just an in-column header + the scroll body. Standalone
   * (default, mobile) renders a full-height themed page with a back affordance.
   */
  embedded?: boolean;
  children: ReactNode;
}

const titleBlock = (title: string, count?: string) => (
  <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
    <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, letterSpacing: 'var(--tracking-tight)', color: 'var(--text-strong)' }}>{title}</span>
    {count != null && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{count}</span>}
  </div>
);

const headerInner = (title: string, count?: string, actions?: ReactNode) => (
  <>
    {titleBlock(title, count)}
    <div style={{ flex: 1 }} />
    {actions}
  </>
);

/**
 * Wrapper for the account screens (Settings, Contacts, Devices, Admin). Standalone
 * (mobile / direct nav) gives a full-height themed page with a back button.
 * Embedded (desktop, inside the app shell) drops the themed root + back button and
 * renders just an in-column header + body, so the section lives in the inbox layout.
 */
export function PageShell({ title, count, actions, headerContent, theme, density, embedded, children }: PageShellProps) {
  const navigate = useNavigate();

  if (embedded) {
    return (
      <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <div style={{
          padding: 'var(--space-3) var(--space-4)', flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
          background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
        }}>
          {headerInner(title, count, actions)}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>{children}</div>
      </div>
    );
  }

  const resolvedDensity = density ?? readDensity();
  return (
    <div
      data-theme={theme ?? readTheme()}
      data-density={resolvedDensity === 'compact' ? 'compact' : undefined}
      style={{
        minHeight: '100dvh', display: 'flex', flexDirection: 'column',
        background: 'var(--surface-page)', color: 'var(--text-body)',
        fontFamily: 'var(--font-sans)', WebkitFontSmoothing: 'antialiased',
      }}
    >
      <header style={{
        height: 'calc(60px + env(safe-area-inset-top))', flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
        padding: 'env(safe-area-inset-top) var(--space-4) 0', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
      }}>
        {headerContent
          ? <div style={{ flex: 1, minWidth: 0 }}>{headerContent}</div>
          : <><IconButton aria-label="Back to inbox" onClick={() => navigate('/inbox')}><Icon name="chevron-left" /></IconButton>{titleBlock(title, count)}</>}
        {!headerContent && <div style={{ flex: 1 }} />}
        {actions}
      </header>
      <div style={{ flex: 1, overflowY: 'auto' }}>{children}</div>
    </div>
  );
}
