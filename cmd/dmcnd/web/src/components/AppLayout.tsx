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
import { countUnread } from '../lib/unread';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { loadLocalKeystore } from '../lib/crypto/localKeystore';
import { LabelManager } from './LabelManager';
import { AccountMenu } from './AccountMenu';
import { NavRow } from './NavRow';
import { useStorageMode } from '../lib/hooks/useStorageMode';
import { deployment } from '@deployment';

import { Button, IconButton, Input } from '../ds';
import { Icon } from './Icon';
import { ComposeDialog } from './ComposeDialog';
import type { ComposeReplyTo } from '../lib/compose';

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
 * Devices / Settings / Admin) render standalone (full screen) instead.
 */
export function AppLayout() {
  const { messages, refresh } = useMessages();
  const { refreshSent } = useSent();
  const { flags } = useFlags();
  const { labels, folders } = useLabels();
  const { filter: mailFilter } = useMailFilter();
  const [labelManagerOpen, setLabelManagerOpen] = useState(false);
  const { address, clearSession } = useAuth();
  const { clearKeys, clearAllKeys } = useKeys();
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
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  // Whether this relay hosts personal storage at all. False until the first storage call
  // comes back UNSUPPORTED, so the banner appears as soon as we actually know.
  const { localOnly: storageLocalOnly } = useStorageMode();
  const AppNav = deployment.appNav;
  // Temporary (single-session) sign-in on a shared computer: nothing is stored here.
  // Derived from the absence of an encrypted keystore rather than a flag, so it stays
  // correct when the account switcher moves the tab to (or off) such a session.
  const [ephemeral, setEphemeral] = useState(false);

  const theme = resolveTheme(themePref);

  useEffect(() => {
    let cancelled = false;
    if (!address) { setEphemeral(false); return; }
    void loadLocalKeystore(address).then(ks => { if (!cancelled) setEphemeral(ks === null); });
    return () => { cancelled = true; };
  }, [address]);

  useEffect(() => { writeThemePref(themePref); }, [themePref]);
  useEffect(() => { writeDensity(compact ? 'compact' : 'comfortable'); }, [compact]);
  useEffect(() => { if (!isMobile) { setDrawerOpen(false); setSearchOpen(false); } }, [isMobile]);
  // Search/filter only applies to the mail list; reset it when leaving mail.
  useEffect(() => { if (section !== 'mail') { setSearchOpen(false); setFilter(''); } }, [section]);
  // Honor the ?compose=1 PWA shortcut on first load.
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get('compose')) setCompose({ replyTo: null });
  }, []);

  // One combined inbox: every unread received message except blocked senders (trust is
  // decided at read time by the reader's gate, not by list placement). The rule lives in
  // lib/unread so the account switcher's per-account counts mean the same thing.
  const unreadCount = countUnread(messages, address, flags, mailFilter);

  const handleSignOut = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    await clearKeys(); // drop the working handle (locks the account; removes a temp handle)
    clearSession();
    navigate('/login');
  };

  // Leaving a shared machine: lock every account this tab holds, not just the one
  // in front of us. The others stay listed on the picker, they just need unlocking.
  const handleSignOutAll = async () => {
    try { await apiLogout(); } catch { /* ignore */ }
    await clearAllKeys();
    clearSession();
    navigate('/login');
  };

  // A switch re-homes every provider on its own (they key off the session and keys);
  // what's left is shell state that belonged to the account we just left.
  const handleSwitched = () => {
    setCompose(null);
    setLabelManagerOpen(false);
    setFolder('inbox');
    setFilter('');
    setSearchOpen(false);
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
      {/* Off-canvas on a phone, the closed drawer is not part of the page: inert keeps its
          controls out of the tab order and away from clicks, aria-hidden out of the
          accessibility tree — otherwise "the first Compose button" is one nobody can see. */}
      <nav style={sidebarStyle} inert={isMobile && !drawerOpen} aria-hidden={isMobile && !drawerOpen}>
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
          {/* On mobile the header trigger is a bare monogram; this is the labelled
              way in, and it opens the same sheet. */}
          {isMobile && (
            <NavRow icon="user" label="Switch account" collapsed={railCollapsed} onClick={() => { setDrawerOpen(false); setSearchOpen(false); setAccountMenuOpen(true); }} />
          )}
          <NavRow icon="users" label="Contacts" active={section === 'contacts'} collapsed={railCollapsed} onClick={() => goto('/contacts')} />
          {AppNav && <AppNav collapsed={railCollapsed} pathname={location.pathname} goto={goto} />}
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
            {deployment.branding.appMark}
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
            {/* The signed-in account is identified by its ADDRESS: that's what the
                mesh routes to, what recipients see, and the only way to tell two
                accounts apart. It doubles as the switcher between the identities
                unlocked in this tab. */}
            <AccountMenu
              open={accountMenuOpen}
              onOpenChange={setAccountMenuOpen}
              mobile={isMobile}
              onSignOut={handleSignOut}
              onSignOutAll={handleSignOutAll}
              onSwitched={handleSwitched}
              draftOpen={compose !== null}
            />
          </header>
        )}

        {/* A relay that hosts no personal storage is a valid deployment, but it means Sent,
            contacts, flags and settings are being kept in THIS browser only. Said out loud
            because the alternative is that someone opens a second device, finds an empty Sent
            folder, and reasonably concludes their mail was lost. */}
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
