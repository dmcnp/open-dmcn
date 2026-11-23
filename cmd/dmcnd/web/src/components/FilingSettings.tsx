import { useState } from 'react';
import { Switch } from '../ds';
import { SettingsSection } from './SettingsSection';
import { ConfirmTrashButton } from './ConfirmTrashButton';
import { Icon } from './Icon';
import { useSettings } from '../lib/hooks/useSettings';
import { useLabels } from '../lib/hooks/useLabels';
import { useContacts } from '../lib/hooks/useContacts';
import { useIsMobile } from '../lib/useIsMobile';
import { asksAboutSender, fullSwipeArchives, rulesByFolder, rulesOf, withoutRule } from '../lib/filing';

// Filing's settings, beside the folders they file into: whether moving a message asks about the
// sender's other mail, what a full swipe left does (phones only: there is no swipe with a
// pointer), and the sender rules, grouped under their folders, each with a way to stop it.
// All of it is the synced "swipeFiling" field the Apple client shares (lib/filing.ts).

const rowStyle = { display: 'flex', alignItems: 'center', gap: 'var(--space-4)' } as const;
const titleStyle = { fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' } as const;
const descStyle = { fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2 } as const;

export function FilingSettings() {
  const { settings, changeSettings } = useSettings();
  const { folders } = useLabels();
  const { nameFor } = useContacts();
  const mobile = useIsMobile();
  const [error, setError] = useState('');
  const sf = settings.swipeFiling;
  const groups = rulesByFolder(sf, folders);
  const count = rulesOf(sf).length;

  const run = (fn: () => Promise<void>) => {
    setError('');
    void fn().catch(e => setError(e instanceof Error ? e.message : String(e)));
  };
  const set = (patch: { asksAboutSender?: boolean; fullSwipeArchives?: boolean }) =>
    run(() => changeSettings(cur => ({ swipeFiling: { ...cur.swipeFiling, ...patch } })));
  const remove = (sender: string) =>
    run(() => changeSettings(cur => ({ swipeFiling: withoutRule(cur.swipeFiling, sender) })));

  return (
    <div style={{ marginTop: 'var(--space-8)', display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {error && (
        <div style={{ padding: 'var(--space-2) var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>{error}</div>
      )}
      <SettingsSection title="Filing">
        <div style={rowStyle}>
          <div style={{ flex: 1 }}>
            <div style={titleStyle}>Ask about the sender's other mail</div>
            <div style={descStyle}>After you move a message to a folder, ask whether the sender's other mail and new mail should go there too.</div>
          </div>
          <Switch id="filing-asks" checked={asksAboutSender(sf)} onChange={v => set({ asksAboutSender: v })} />
        </div>
        {mobile && (
          <div style={rowStyle}>
            <div style={{ flex: 1 }}>
              <div style={titleStyle}>Full swipe left archives</div>
              <div style={descStyle}>Swiping a message all the way left archives it instead of deleting it.</div>
            </div>
            <Switch id="filing-full-swipe" checked={fullSwipeArchives(sf)} onChange={v => set({ fullSwipeArchives: v })} />
          </div>
        )}
      </SettingsSection>

      <SettingsSection title="Sender rules">
        <div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
            {count === 0
              ? "None yet. When you move a message and choose to always move that sender's mail, it shows here."
              : `${count === 1 ? "1 sender's" : `${count} senders'`} new mail goes straight to a folder. Removing a sender stops filing their new mail. Mail already filed stays where it is.`}
          </div>
          {groups.map(g => (
            <div key={g.folder?.id ?? 'deleted'} style={{ marginTop: 'var(--space-4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)' }}>
                <Icon name="folder" size={14} style={{ color: 'var(--text-muted)' }} />
                {g.folder ? g.folder.name : 'Deleted folders'}
              </div>
              {!g.folder && (
                <div style={{ ...descStyle, marginBottom: 'var(--space-1)' }}>
                  These folders were deleted, so nothing is filed for these senders. Removing them tidies up.
                </div>
              )}
              {g.rules.map(r => {
                const name = nameFor(r.sender);
                return (
                  <div key={r.sender} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) 0 var(--space-2) 22px' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 'var(--text-md)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</div>
                      {name !== r.sender && (
                        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.sender}</div>
                      )}
                    </div>
                    <ConfirmTrashButton size="sm" aria-label={`Stop filing mail from ${r.sender}`} title={`Stop filing mail from ${r.sender}`} onConfirm={() => remove(r.sender)} />
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </SettingsSection>
    </div>
  );
}
