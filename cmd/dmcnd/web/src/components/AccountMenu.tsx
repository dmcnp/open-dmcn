import { CSSProperties, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, MouseEvent as ReactMouseEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useAccountSwitch } from '../lib/hooks/useAccountSwitch';
import { useBackgroundUnread } from '../lib/hooks/useBackgroundUnread';
import type { DeviceAccount } from '../lib/accounts';
import { AccountMonogram } from './AccountMonogram';
import { Icon } from './Icon';
import { Badge, Button, Input } from '../ds';

// The account switcher behind the address in the top bar. Several identities can be
// unlocked in one tab, so moving between them is a click; one that isn't unlocked yet
// unlocks in place (password field here, or the passkey prompt straight from the
// click) rather than sending the user back to the login page.
//
// Not a design-system component: everything under src/ds imports React and nothing
// else, while this needs the session, the key context, WebAuthn and the API layer —
// and its unlock state is a form, which can't live inside role="menu". Same call
// AppLayout makes for its nav rail.

interface AccountMenuProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  mobile: boolean;
  onSignOut: () => void;
  onSignOutAll: () => void;
  // Called after the app has re-homed to another account, so the shell can drop
  // state belonging to the previous one.
  onSwitched?: () => void;
  // An unsent compose is open: switching would silently re-home it to the new
  // identity, so confirm first.
  draftOpen?: boolean;
}

type Action = 'add' | 'settings' | 'signout' | 'signout-all';

const ACTION_LABEL: Record<Action, string> = {
  add: 'Add another account',
  settings: 'Settings',
  signout: 'Sign out',
  'signout-all': 'Sign out of all accounts',
};

const ACTION_ICON: Record<Action, string> = {
  add: 'plus',
  settings: 'settings',
  signout: 'log-out',
  'signout-all': 'log-out',
};

const rowStyle: CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 'var(--space-3)', width: '100%',
  border: 'none', background: 'transparent', font: 'inherit', textAlign: 'left',
  color: 'var(--text-body)', cursor: 'pointer',
};

export function AccountMenu({ open, onOpenChange, mobile, onSignOut, onSignOutAll, onSwitched, draftOpen }: AccountMenuProps) {
  const { address } = useAuth();
  const navigate = useNavigate();
  const [activeIdx, setActiveIdx] = useState(-1);
  const [passphrase, setPassphrase] = useState('');
  // The account a draft-discard confirmation is pending for.
  const [pendingSwitch, setPendingSwitch] = useState<DeviceAccount | null>(null);

  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);

  // The switch hook needs to close the menu, and closing the menu needs to abandon an
  // in-progress unlock the hook owns — a latest-value ref breaks that knot.
  const closeRef = useRef<() => void>(() => { /* assigned below */ });
  const { accounts, refresh, busy, error, needsPassword, beginUnlock, cancelUnlock, switchTo } = useAccountSwitch({
    onSwitched: () => { closeRef.current(); onSwitched?.(); },
  });

  const closeMenu = () => {
    onOpenChange(false);
    setActiveIdx(-1);
    setPendingSwitch(null);
    if (needsPassword) cancelUnlock();
  };
  closeRef.current = closeMenu;

  const others = useMemo(
    () => (accounts ?? []).filter(a => a.address !== address),
    [accounts, address]
  );
  // Unread waiting in the other accounts this tab holds unlocked. The active
  // account's own count is the sidebar's job, not the switcher's.
  const { counts: unread, total: unreadElsewhere, refresh: refreshUnread } = useBackgroundUnread(accounts, address);
  const unlockedCount = (accounts ?? []).filter(a => a.unlocked).length;
  const current = (accounts ?? []).find(a => a.address === address) ?? null;
  // No encrypted keystore for the signed-in address ⇒ a temporary (single-use) session.
  const temporary = current !== null && current.ks === null;

  const actions = useMemo<Action[]>(() => {
    const list: Action[] = ['add', 'settings', 'signout'];
    if (unlockedCount > 1) list.push('signout-all');
    return list;
  }, [unlockedCount]);

  // The account mid-unlock, when it needs a password typed here. A passkey account
  // is already showing the platform prompt, so the menu stays as it is.
  const unlockTarget = needsPassword
    ? others.find(a => a.address === needsPassword && a.ks?.authMethod !== 'passkey') ?? null
    : null;

  const itemCount = others.length + actions.length;

  // Re-read the device's accounts whenever the menu opens: another tab may have
  // added, removed or unlocked one since it was last rendered.
  useEffect(() => {
    if (open) { void refresh(); void refreshUnread(); }
    else { setActiveIdx(-1); setPendingSwitch(null); setPassphrase(''); }
  }, [open, refresh, refreshUnread]);

  // Escape backs out one step: an in-progress unlock first, then the menu.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      if (unlockTarget) { cancelUnlock(); return; }
      onOpenChange(false);
      setActiveIdx(-1);
      setPendingSwitch(null);
      triggerRef.current?.focus();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, unlockTarget, cancelUnlock, onOpenChange]);

  // Keyboard highlight moves focus; the pointer only paints a hover background, so
  // the two never fight over which row is "active".
  useEffect(() => {
    if (open && activeIdx >= 0) itemRefs.current[activeIdx]?.focus();
  }, [open, activeIdx]);

  useEffect(() => {
    if (open && activeIdx < 0 && !unlockTarget) panelRef.current?.focus();
  }, [open, activeIdx, unlockTarget]);

  const startSwitch = (account: DeviceAccount) => {
    setPassphrase('');
    if (account.unlocked) void switchTo(account);
    else beginUnlock(account); // passkey prompts now; password expands the form
  };

  const onAccountClick = (account: DeviceAccount) => {
    if (draftOpen) { setPendingSwitch(account); return; }
    startSwitch(account);
  };

  const runAction = (action: Action) => {
    switch (action) {
      case 'add': closeMenu(); navigate('/login'); break;
      case 'settings': closeMenu(); navigate('/settings'); break;
      case 'signout': closeMenu(); onSignOut(); break;
      case 'signout-all': closeMenu(); onSignOutAll(); break;
    }
  };

  const onPanelKeyDown = (e: ReactKeyboardEvent) => {
    if (unlockTarget || pendingSwitch) return; // a form owns the keyboard
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => (i + 1) % itemCount); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx(i => (i <= 0 ? itemCount - 1 : i - 1)); }
    else if (e.key === 'Home') { e.preventDefault(); setActiveIdx(0); }
    else if (e.key === 'End') { e.preventDefault(); setActiveIdx(itemCount - 1); }
    else if (e.key === 'Tab') { closeMenu(); }
  };

  const onTriggerKeyDown = (e: ReactKeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); onOpenChange(true); setActiveIdx(0); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); onOpenChange(true); setActiveIdx(itemCount - 1); }
  };

  const hoverOn = (e: ReactMouseEvent<HTMLElement>) => { e.currentTarget.style.background = 'var(--surface-hover)'; };
  const hoverOff = (e: ReactMouseEvent<HTMLElement>) => { e.currentTarget.style.background = 'transparent'; };

  // Anchored under the trigger in every size. A bottom sheet was tried on mobile and
  // reads as a different control entirely: you tap the top-right corner and something
  // rises from the far end of the screen, disconnected from what you touched. The
  // panel is small enough to fit a phone (320 wide, clamped to the viewport), so the
  // one placement that always points back at its trigger wins.
  const panelStyle: CSSProperties = {
    position: 'absolute', top: 'calc(100% + 6px)', right: 0, zIndex: 46,
    width: 320, maxWidth: 'calc(100vw - var(--space-4))',
    maxHeight: mobile ? '70dvh' : '70vh', overflowY: 'auto',
    background: 'var(--surface-card)', border: '1px solid var(--border-default)',
    borderRadius: 'var(--radius-lg)', boxShadow: 'var(--shadow-lg)',
  };

  const accountRowPadding = mobile ? '12px 16px' : '10px 12px';

  return (
    <div style={{ position: 'relative' }}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls="dmcn-account-menu"
        aria-label={
          address
            ? `Account: ${address}${unreadElsewhere > 0 ? ` — ${unreadElsewhere} unread in your other accounts` : ''}`
            : 'Account'
        }
        title={address ?? undefined}
        disabled={!address}
        onClick={() => (open ? closeMenu() : onOpenChange(true))}
        onKeyDown={onTriggerKeyDown}
        style={{
          display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginLeft: 'var(--space-1)',
          height: 38, padding: '0 var(--space-2)', border: 'none', borderRadius: 'var(--radius-md)',
          font: 'inherit', color: 'var(--text-muted)', cursor: address ? 'pointer' : 'default',
          background: open ? 'var(--surface-hover)' : 'transparent',
          // Above the scrim while open, so clicking the trigger again closes the menu
          // instead of the scrim swallowing the press and the click reopening it.
          position: 'relative', zIndex: open ? 47 : undefined,
        }}
        onMouseEnter={e => { if (!open) e.currentTarget.style.background = 'var(--surface-hover)'; }}
        onMouseLeave={e => { if (!open) e.currentTarget.style.background = 'transparent'; }}
      >
        {address && (
          <span style={{ position: 'relative', display: 'inline-flex', flex: 'none' }}>
            <AccountMonogram address={address} size={26} />
            {/* Mail is waiting in an account that isn't the one on screen. Deliberately
                a dot rather than a number: the count that matters is per account, and
                it's one click away in the panel. */}
            {unreadElsewhere > 0 && (
              <span aria-hidden="true" style={{
                position: 'absolute', top: -2, right: -2, width: 8, height: 8, borderRadius: '50%',
                background: 'var(--brand)', boxShadow: '0 0 0 2px var(--surface-card)',
              }} />
            )}
          </span>
        )}
        {!mobile && address && (
          <span style={{
            maxWidth: 220, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>{address}</span>
        )}
        <Icon name="chevron-down" size={14} />
      </button>

      {open && (
        <>
          <div
            aria-hidden="true"
            onMouseDown={() => closeMenu()}
            style={{
              position: 'fixed', inset: 0, zIndex: 45,
              // Transparent everywhere now that the panel is anchored: a dimmed screen
              // belongs to a sheet, and dimming behind a small dropdown just makes the
              // app look modal when it isn't.
              background: 'transparent',
            }}
          />
          <div
            id="dmcn-account-menu"
            ref={panelRef}
            tabIndex={-1}
            role={unlockTarget || pendingSwitch ? 'dialog' : 'menu'}
            aria-modal={unlockTarget || pendingSwitch ? false : undefined}
            aria-label={unlockTarget ? `Unlock ${unlockTarget.address}` : 'Accounts'}
            onKeyDown={onPanelKeyDown}
            style={{ ...panelStyle, outline: 'none' }}
          >
            {unlockTarget ? (
              <form
                onSubmit={e => { e.preventDefault(); void switchTo(unlockTarget, { password: passphrase }); }}
                style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', padding: 'var(--space-4)' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                  <AccountMonogram address={unlockTarget.address} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {unlockTarget.address}
                    </div>
                    <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Unlock to switch</div>
                  </div>
                </div>
                <Input label="Password" type="password" value={passphrase} onChange={e => setPassphrase(e.target.value)} autoFocus />
                {error && <div role="alert" style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{error}</div>}
                <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                  <Button size="sm" type="submit" disabled={busy}>{busy ? 'Unlocking…' : 'Unlock'}</Button>
                  <Button size="sm" variant="secondary" type="button" disabled={busy} onClick={cancelUnlock}>Cancel</Button>
                </div>
              </form>
            ) : pendingSwitch ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', padding: 'var(--space-4)' }}>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-body)', lineHeight: 'var(--leading-normal)' }}>
                  You have a message open that hasn't been sent. Switching to{' '}
                  <span style={{ fontFamily: 'var(--font-mono)' }}>{pendingSwitch.address}</span> discards it.
                </div>
                <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                  <Button size="sm" onClick={() => { const a = pendingSwitch; setPendingSwitch(null); startSwitch(a); }}>Discard and switch</Button>
                  <Button size="sm" variant="secondary" onClick={() => setPendingSwitch(null)}>Cancel</Button>
                </div>
              </div>
            ) : (
              <>
                {address && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: mobile ? '16px' : 'var(--space-3)' }}>
                    <AccountMonogram address={address} />
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {address}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2, fontSize: 'var(--text-xs)', color: temporary ? 'var(--warning)' : 'var(--brand-text)' }}>
                        <Icon name={temporary ? 'alert-triangle' : 'shield-check'} size={11} />
                        {temporary ? 'Temporary session' : 'Signed in'}
                      </div>
                    </div>
                  </div>
                )}

                {others.length > 0 && (
                  <div style={{ borderTop: '1px solid var(--border-subtle)', padding: 'var(--space-1) 0' }}>
                    {others.map((account, i) => (
                      <button
                        key={account.address}
                        ref={el => { itemRefs.current[i] = el; }}
                        type="button"
                        role="menuitem"
                        tabIndex={-1}
                        disabled={busy}
                        onClick={() => onAccountClick(account)}
                        onMouseEnter={hoverOn}
                        onMouseLeave={hoverOff}
                        style={{ ...rowStyle, padding: accountRowPadding }}
                      >
                        <AccountMonogram address={account.address} size={26} />
                        <span style={{ flex: '1 1 0', minWidth: 0 }}>
                          <span style={{ display: 'block', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {account.address}
                          </span>
                          <span style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 2, fontSize: 'var(--text-xs)', color: account.unlocked ? 'var(--brand-text)' : 'var(--text-muted)' }}>
                            <Icon name={account.unlocked ? 'shield-check' : 'lock'} size={11} />
                            {account.unlocked ? 'Unlocked' : 'Locked'}
                          </span>
                        </span>
                        {account.unlocked
                          ? (unread.get(account.address) ?? 0) > 0 && (
                              <Badge
                                variant="solid"
                                title={`${unread.get(account.address)} unread`}
                                style={{ flex: 'none', fontVariantNumeric: 'tabular-nums' }}
                              >
                                {Math.min(unread.get(account.address) ?? 0, 999)}
                              </Badge>
                            )
                          // A locked account's mail is unreadable from here — no key, so no
                          // count. Unlocking it is what makes one appear.
                          : <span style={{ flex: 'none', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Unlock</span>}
                      </button>
                    ))}
                  </div>
                )}

                {error && (
                  <div role="alert" style={{ padding: '0 var(--space-3) var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>
                    {error}
                  </div>
                )}

                <div style={{ borderTop: '1px solid var(--border-subtle)', padding: 'var(--space-1) 0' }}>
                  {actions.map((action, j) => (
                    <button
                      key={action}
                      ref={el => { itemRefs.current[others.length + j] = el; }}
                      type="button"
                      role="menuitem"
                      tabIndex={-1}
                      onClick={() => runAction(action)}
                      onMouseEnter={hoverOn}
                      onMouseLeave={hoverOff}
                      style={{ ...rowStyle, padding: mobile ? '12px 16px' : '9px 12px', fontSize: 'var(--text-sm)' }}
                    >
                      <Icon name={ACTION_ICON[action]} size={16} style={{ color: 'var(--text-muted)', flex: 'none' }} />
                      <span>{ACTION_LABEL[action]}</span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
