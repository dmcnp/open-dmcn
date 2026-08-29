// NavRow is one row in the app's left rail. Its own module because a deployment contributes
// rows for the sections it adds (see lib/deployment.ts appNav), and those must look like the
// built-in ones rather than approximate them.
import { Icon } from './Icon';

export function NavRow({ icon, swatch, label, active, count, badge, collapsed, onClick }: {
  icon?: string; swatch?: string; label: string; active?: boolean; count?: number; badge?: boolean; collapsed: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      title={collapsed ? label : undefined}
      style={{
        position: 'relative', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', width: '100%',
        padding: collapsed ? 0 : '0 var(--space-3)', justifyContent: collapsed ? 'center' : 'flex-start',
        height: 36, border: 'none', cursor: 'pointer',
        background: active ? 'var(--brand-subtle)' : 'transparent',
        color: active ? 'var(--brand-text)' : 'var(--text-body)',
        borderLeft: active ? '2px solid var(--brand)' : '2px solid transparent',
        font: 'inherit', fontSize: 'var(--text-md)',
        fontWeight: active ? 'var(--weight-semibold)' : 'var(--weight-medium)',
        textAlign: 'left', transition: 'background var(--dur-fast) var(--ease-standard)',
      }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = 'var(--surface-hover)'; }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
    >
      {swatch
        ? <span style={{ width: 12, height: 12, borderRadius: '50%', background: swatch, flex: 'none' }} />
        : <Icon name={icon ?? 'inbox'} size={17} style={{ color: active ? 'var(--brand)' : 'var(--text-muted)' }} />}
      {!collapsed && <span style={{ flex: 1 }}>{label}</span>}
      {!collapsed && count != null && count > 0 && (
        <span style={{ fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-semibold)', color: active ? 'var(--brand-text)' : 'var(--text-muted)' }}>{count}</span>
      )}
      {badge && (
        <span style={{
          position: collapsed ? 'absolute' : 'static', top: collapsed ? 6 : undefined, right: collapsed ? 14 : undefined,
          minWidth: 7, height: 7, borderRadius: 999, background: 'var(--warning)', flex: 'none',
        }} />
      )}
    </button>
  );
}
