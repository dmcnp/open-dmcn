import { useEffect, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { useMessages } from '../lib/hooks/useMessages';
import { useSent } from '../lib/hooks/useSent';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { useIsMobile } from '../lib/useIsMobile';
import { readThemePref, resolveTheme, readDensity, writeThemePref, writeDensity, type ThemePref } from '../lib/theme';
import { logout as apiLogout } from '../lib/api/client';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import { useSettings } from '../lib/hooks/useSettings';
import { useContacts } from '../lib/hooks/useContacts';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { categorizeSender } from '../lib/trust/category';
import { isReceivedForMe } from '../lib/mailView';
import { LabelManager } from './LabelManager';

// The open protocol carries no control messages (device pairing + countersign requests
// are product surfaces), so nothing is excluded from the inbox. Kept as an (empty) set so
// the shared list-filtering logic is unchanged. In sync with InboxMain's CONTROL_SUBJECTS.
const CONTROL_SUBJECTS = new Set<string>([]);
import { Button, IconButton, Input } from '../ds';
import { AccountMonogram } from './AccountMonogram';
import { Icon } from './Icon';
import { ComposeDialog, type ComposeReplyTo } from './ComposeDialog';
import { DEFAULT_DOMAIN } from '../lib/config';
import { useStorageMode } from '../lib/hooks/useStorageMode';

// System folders plus dynamic selectors for a user label ("label:<id>") or user
// folder ("folder:<id>"). InboxMain parses the dynamic forms.
type Folder = 'inbox' | 'sent' | 'archive' | 'starred' | `label:${string}` | `folder:${string}`;
type Section = 'mail' | 'contacts' | 'settings';

// Shared state the shell hands to the active section via react-router's outlet
// context. InboxMain consumes folder/filter/openCompose; Settings consumes
// onAppearanceChange (to re-theme the whole shell live on desktop).
export interface MailOutletContext {
  folder: Folder;
  filter: string;
  openCompose: (replyTo: ComposeReplyTo | null) => void;
  onAppearanceChange: () => void;
}

function sectionFromPath(p: string): Section {
  if (p.startsWith('/contacts')) return 'contacts';
  if (p.startsWith('/settings')) return 'settings';
  return 'mail';
}

// --- sidebar primitives (app-level; the DS ships components, not a nav rail) ---

function NavRow({ icon, swatch, label, active, count, badge, collapsed, onClick }: {
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

function GroupLabel({ children, collapsed }: { children: ReactNode; collapsed: boolean }) {
  if (collapsed) return <div style={{ height: 1, background: 'var(--border-subtle)', margin: 'var(--space-3)' }} />;
  return (
    <div style={{ padding: 'var(--space-4) var(--space-4) var(--space-2)', fontSize: 'var(--text-2xs)', letterSpacing: 'var(--tracking-caps)', textTransform: 'uppercase', color: 'var(--text-subtle)', fontWeight: 'var(--weight-semibold)' }}>
      {children}
    </div>
  );
}

/**
 * The persistent app shell — sidebar + top bar + floating compose — that wraps
 * every authenticated screen via a react-router layout route. Child sections
 * render in the main column through <Outlet/>, so the chrome (and an in-progress
 * compose) survives section switches. On mobile, account sections (Contacts /
 * Settings) render standalone (full screen) instead.
 */
export function AppLayout() {
  const { messages, refresh } = useMessages();
  const { refreshSent } = useSent();
  const { isRead, isArchived } = useFlags();
  const { labels, folders } = useLabels();
  const { settings } = useSettings();
  const { contactByAddress } = useContacts();
  const { filter: mailFilter } = useMailFilter();
  const [labelManagerOpen, setLabelManagerOpen] = useState(false);
  const { address, clearSession } = useAuth();
  const displayName = settings.displayName || address;
  const { clearKeys } = useKeys();
  const navigate = useNavigate();
  const location = useLocation();
  const isMobile = useIsMobile();
  const section = sectionFromPath(location.pathname);

  const [folder, setFolder] = useState<Folder>('inbox');
  const [filter, setFilter] = useState('');
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [compact, setCompact] = useState(() => readDensity() === 'compact');
  const [themePref, setThemePref] = useState<ThemePref>(readThemePref);
  const [compose, setCompose] = useState<{ replyTo: ComposeReplyTo | null } | null>(null);
  // Temporary (single-session) sign-in on a shared computer: nothing is stored here.
  const [ephemeral] = useState(() => { try { return sessionStorage.getItem('dmcn_ephemeral') === '1'; } catch { return false; } });
  // Whether this relay hosts personal storage. False-by-default and flips once the first
  // storage call comes back UNSUPPORTED, so the banner appears as soon as we actually know.
  const { localOnly: storageLocalOnly } = useStorageMode();

  const theme = resolveTheme(themePref);

  useEffect(() => { writeThemePref(themePref); }, [themePref]);
  useEffect(() => { writeDensity(compact ? 'compact' : 'comfortable'); }, [compact]);
  useEffect(() => { if (!isMobile) { setDrawerOpen(false); setSearchOpen(false); } }, [isMobile]);
  // Search/filter only applies to the mail list; reset it when leaving mail.
  useEffect(() => { if (section !== 'mail') { setSearchOpen(false); setFilter(''); } }, [section]);
  // Honor the ?compose=1 PWA shortcut on first load.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('compose')) setCompose({ replyTo: null });
  }, []);

  // Received, non-control, non-archived mail, split by trust category (§14.2) so the
  // Inbox is one combined list — unread count covers every non-blocked sender, since
  // trust is decided at read time rather than by splitting the list.
  const liveReceived = messages.filter(m =>
    isReceivedForMe(m, address) && !CONTROL_SUBJECTS.has(m.subject) && !isArchived(m.hash)
  );
  // My own address is inherently trusted, so mail I sent myself counts as allowlisted
  // (Inbox), mirroring InboxMain's view filter so the badges match the lists.
  const catOf = (m: typeof messages[number]) =>
    address != null && m.senderAddress.toLowerCase() === address.toLowerCase()
      ? 'allowlisted' as const
      : categorizeSender(m.senderAddress, m.senderPublicKey, contactByAddress(m.senderAddress), mailFilter);
  const unreadCount = liveReceived.filter(m => !isRead(m.hash) && catOf(m) === 'allowlisted').length;

  const handleSignOut = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    await clearKeys(); // drop the working handle (locks the account; removes a temp handle)
    clearSession();
    navigate('/login');
  };

  const selectFolder = (f: Folder) => {
    setFolder(f);
    setDrawerOpen(false);
    if (section !== 'mail') navigate('/inbox');
  };
  const goto = (path: string) => { setDrawerOpen(false); navigate(path); };
  const openCompose = (replyTo: ComposeReplyTo | null) => { setCompose({ replyTo }); setDrawerOpen(false); };
  const onMenu = () => { if (isMobile) setDrawerOpen(o => !o); else setCollapsed(c => !c); };
  // Re-read appearance after Settings writes it, so the shell re-themes live.
  const onAppearanceChange = () => { setThemePref(readThemePref()); setCompact(readDensity() === 'compact'); };

  const outletCtx: MailOutletContext = { folder, filter, openCompose, onAppearanceChange };

  // Mobile account sections render standalone (no shell chrome); the page provides
  // its own PageShell. Mail (and all of desktop) gets the full shell.
  if (isMobile && section !== 'mail') {
    return <Outlet context={outletCtx} />;
  }

  const railCollapsed = isMobile ? false : collapsed;

  const sidebarStyle: CSSProperties = isMobile
    ? {
        position: 'fixed', top: 0, left: 0, height: '100%', width: 'var(--rail-nav)', maxWidth: '84vw',
        zIndex: 60, transform: drawerOpen ? 'translateX(0)' : 'translateX(-100%)',
        boxShadow: drawerOpen ? 'var(--shadow-lg)' : 'none',
        transition: 'transform var(--dur-normal) var(--ease-out)',
        background: 'var(--surface-card)', borderRight: '1px solid var(--border-default)',
        display: 'flex', flexDirection: 'column', boxSizing: 'border-box', paddingTop: 'env(safe-area-inset-top)',
      }
    : {
        width: railCollapsed ? 'var(--rail-nav-min)' : 'var(--rail-nav)', flex: 'none',
        background: 'var(--surface-card)', borderRight: '1px solid var(--border-default)',
        display: 'flex', flexDirection: 'column', height: '100%',
        transition: 'width var(--dur-normal) var(--ease-standard)', overflow: 'hidden',
      };

  return (
    <div
      data-theme={theme}
      data-density={compact ? 'compact' : undefined}
      style={{
        display: 'flex', height: '100dvh', overflow: 'hidden',
        background: 'var(--surface-page)', color: 'var(--text-body)',
        fontFamily: 'var(--font-sans)', WebkitFontSmoothing: 'antialiased',
      }}
    >
      {/* ---- Sidebar / drawer ---- */}
      {isMobile && (
        <div onClick={() => setDrawerOpen(false)} aria-hidden="true" style={{
          position: 'fixed', inset: 0, zIndex: 55, background: 'rgba(12,16,16,0.45)',
          opacity: drawerOpen ? 1 : 0, pointerEvents: drawerOpen ? 'auto' : 'none',
          transition: 'opacity var(--dur-normal) var(--ease-standard)',
        }} />
      )}
      <nav style={sidebarStyle}>
        <div style={{ padding: railCollapsed ? 'var(--space-3) 0' : 'var(--space-4)', display: 'flex', justifyContent: 'center' }}>
          {railCollapsed ? (
            <IconButton variant="solid" size="lg" aria-label="Compose" onClick={() => openCompose(null)}>
              <Icon name="pencil" size={18} />
            </IconButton>
          ) : (
            <Button fullWidth size="lg" leftIcon={<Icon name="pencil" size={18} />} onClick={() => openCompose(null)}>
              Compose
            </Button>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', overflowY: 'auto', flex: 1 }}>
          <NavRow icon="inbox" label="Inbox" active={section === 'mail' && folder === 'inbox'} count={unreadCount || undefined} collapsed={railCollapsed} onClick={() => selectFolder('inbox')} />
          <NavRow icon="star" label="Starred" active={section === 'mail' && folder === 'starred'} collapsed={railCollapsed} onClick={() => selectFolder('starred')} />
          <NavRow icon="send" label="Sent" active={section === 'mail' && folder === 'sent'} collapsed={railCollapsed} onClick={() => selectFolder('sent')} />
          <NavRow icon="archive" label="Archive" active={section === 'mail' && folder === 'archive'} collapsed={railCollapsed} onClick={() => selectFolder('archive')} />

          {folders.length > 0 && (
            <>
              <GroupLabel collapsed={railCollapsed}>Folders</GroupLabel>
              {folders.map(f => (
                <NavRow key={f.id} icon="archive" label={f.name} active={section === 'mail' && folder === `folder:${f.id}`} collapsed={railCollapsed} onClick={() => selectFolder(`folder:${f.id}`)} />
              ))}
            </>
          )}

          <GroupLabel collapsed={railCollapsed}>Labels</GroupLabel>
          {labels.map(l => (
            <NavRow key={l.id} swatch={l.color} label={l.name} active={section === 'mail' && folder === `label:${l.id}`} collapsed={railCollapsed} onClick={() => selectFolder(`label:${l.id}`)} />
          ))}
          <NavRow icon="settings" label="Manage labels" collapsed={railCollapsed} onClick={() => setLabelManagerOpen(true)} />

          <GroupLabel collapsed={railCollapsed}>Account</GroupLabel>
          <NavRow icon="users" label="Contacts" active={section === 'contacts'} collapsed={railCollapsed} onClick={() => goto('/contacts')} />
          <NavRow icon="settings" label="Settings" active={section === 'settings'} collapsed={railCollapsed} onClick={() => goto('/settings')} />
        </div>

        <div style={{ borderTop: '1px solid var(--border-subtle)' }}>
          <button onClick={handleSignOut} title={railCollapsed ? 'Sign out' : undefined} style={{
            display: 'flex', alignItems: 'center', gap: 'var(--space-3)', width: '100%',
            padding: railCollapsed ? 0 : '0 var(--space-3)', justifyContent: railCollapsed ? 'center' : 'flex-start',
            height: 40, border: 'none', background: 'transparent', cursor: 'pointer', font: 'inherit',
            fontSize: 'var(--text-md)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', textAlign: 'left',
          }}
            onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-hover)'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <Icon name="log-out" size={17} style={{ color: 'var(--text-muted)' }} />
            {!railCollapsed && <span>Sign out</span>}
          </button>
          <div title={railCollapsed ? 'End-to-end encrypted' : undefined} style={{
            padding: railCollapsed ? 'var(--space-3) 0' : 'var(--space-3) var(--space-4)', display: 'flex', alignItems: 'center',
            justifyContent: railCollapsed ? 'center' : 'flex-start', gap: 'var(--space-2)', borderTop: '1px solid var(--border-subtle)',
          }}>
            <Icon name="shield-check" size={16} style={{ color: 'var(--brand)' }} />
            {!railCollapsed && <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>End-to-end encrypted</span>}
          </div>
        </div>
      </nav>

      {/* ---- Main column ---- */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, position: 'relative' }}>
        {/* Top bar */}
        {isMobile && searchOpen && section === 'mail' ? (
          <header style={{
            height: 'calc(60px + env(safe-area-inset-top))', flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
            padding: 'env(safe-area-inset-top) var(--space-3) 0', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
          }}>
            <IconButton aria-label="Close search" onClick={() => { setSearchOpen(false); setFilter(''); }}><Icon name="chevron-left" /></IconButton>
            <div style={{ flex: 1 }}>
              <Input autoFocus leadingIcon={<Icon name="search" size={16} />} placeholder="Filter encrypted mail" aria-label="Filter" value={filter} onChange={e => setFilter(e.target.value)} />
            </div>
            {filter && <IconButton aria-label="Clear" onClick={() => setFilter('')}><Icon name="x" /></IconButton>}
          </header>
        ) : (
          <header style={{
            height: 'calc(60px + env(safe-area-inset-top))', flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
            padding: 'env(safe-area-inset-top) var(--space-4) 0', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
          }}>
            <IconButton aria-label={isMobile ? 'Open menu' : 'Toggle navigation'} active={!isMobile && collapsed} onClick={onMenu}>
              <Icon name={isMobile ? 'menu' : 'panel-left'} />
            </IconButton>
            {/* The deployment's own domain, not a product mark. This client is unbranded;
                the useful thing to show here is WHICH server you are signed in to. */}
            {DEFAULT_DOMAIN && (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontWeight: 600, fontSize: 'var(--text-md)', color: 'var(--text-strong)', marginRight: 'var(--space-2)', whiteSpace: 'nowrap' }}>
                <Icon name="mail" size={17} style={{ color: 'var(--text-muted)' }} />
                {DEFAULT_DOMAIN}
              </span>
            )}
            {!isMobile && section === 'mail' && (
              <div style={{ flex: 1, maxWidth: 620 }}>
                <Input
                  leadingIcon={<Icon name="search" size={16} />}
                  placeholder="Filter encrypted mail"
                  aria-label="Filter"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                />
              </div>
            )}
            <div style={{ flex: 1 }} />
            {isMobile && section === 'mail' && (
              <IconButton aria-label="Filter mail" onClick={() => setSearchOpen(true)}><Icon name="search" /></IconButton>
            )}
            {!isMobile && (
              <IconButton aria-label="Toggle density" active={compact} onClick={() => setCompact(c => !c)}>
                <Icon name="rows" />
              </IconButton>
            )}
            <IconButton aria-label="Toggle theme" onClick={() => setThemePref(theme === 'dark' ? 'light' : 'dark')}>
              <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
            </IconButton>
            {!isMobile && (
              <IconButton aria-label="Settings" active={section === 'settings'} onClick={() => navigate('/settings')}>
                <Icon name="settings" />
              </IconButton>
            )}
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginLeft: 'var(--space-1)' }}>
              <AccountMonogram address={address || '?'} size={32} />
              {!isMobile && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }} title={address ?? undefined}>{displayName}</span>}
            </div>
          </header>
        )}

        {/* This relay hosts no personal storage, so Sent, contacts, flags and settings are
            being kept in THIS browser only. Said out loud because the alternative is that
            someone opens a second device, finds an empty Sent folder, and reasonably
            concludes their mail was lost. */}
        {storageLocalOnly && (
          <div style={{
            flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
            padding: 'var(--space-2) var(--space-4)', background: 'var(--surface-sunken)',
            borderBottom: '1px solid var(--border-default)', fontSize: 'var(--text-sm)', color: 'var(--text-body)',
          }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none' }} />
            <span style={{ flex: 1 }}>
              This server doesn't store your mailbox state, so your sent mail, contacts and settings
              are saved in this browser only — they won't appear on your other devices.
            </span>
          </div>
        )}

        {ephemeral && (
          <div style={{
            flex: 'none', display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
            padding: 'var(--space-2) var(--space-4)', background: 'var(--surface-sunken)',
            borderBottom: '1px solid var(--border-default)', fontSize: 'var(--text-sm)', color: 'var(--text-body)',
          }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none' }} />
            <span style={{ flex: 1 }}>Temporary session — your keys aren't saved for re-login on this device. Sign out when you're done.</span>
            <Button size="sm" variant="secondary" onClick={handleSignOut}>Sign out</Button>
          </div>
        )}

        <Outlet context={outletCtx} />

        {compose && (
          <ComposeDialog
            replyTo={compose.replyTo}
            onClose={() => setCompose(null)}
            onSent={() => { refresh(); refreshSent(); }}
            mobile={isMobile}
          />
        )}

        <LabelManager open={labelManagerOpen} onClose={() => setLabelManagerOpen(false)} />
      </div>
    </div>
  );
}
