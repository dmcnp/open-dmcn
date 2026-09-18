import { useState } from 'react';
import { useLabels, LABEL_COLORS } from '../lib/hooks/useLabels';
import { Button, Input, IconButton } from '../ds';
import { SettingsSection } from './SettingsSection';
import { ColorSwatches } from './ColorSwatches';
import { Icon } from './Icon';

// Naming labels and folders — create, rename, recolour, delete. It writes to the
// "settings/labels" doc (via useLabels, compare-and-swap). Assignment to messages happens in the
// reader; this only names them. Deleting a definition removes it from every view automatically
// (unknown ids are ignored) — no per-message cleanup.
//
// This used to be a dialog reached from a "Manage labels" row in the left rail, and that was wrong
// twice over. The rail is a list of PLACES and a row that opens a modal is not one; and the row was
// labelled for labels while being the only door to folders, so a first folder could only be made by
// someone who went looking for it under the wrong name. Both now live here, as two peer sections,
// which is also where the definitions were all along — they are one key in the personal settings
// doc. Creating one in the moment it is wanted stayed behind in the reader, where the need arises.

// Identifies the row currently being renamed inline (null ⇒ nothing is being edited).
type Editing = { kind: 'label' | 'folder'; id: string } | null;

const rowStyle = { display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) 0' } as const;
const emptyStyle = { fontSize: 'var(--text-sm)', color: 'var(--text-muted)' } as const;

export function LabelSettings() {
  const { labels, folders, createLabel, renameLabel, deleteLabel, createFolder, renameFolder, deleteFolder } = useLabels();
  const [labelName, setLabelName] = useState('');
  const [labelColor, setLabelColor] = useState(LABEL_COLORS[0]);
  const [folderName, setFolderName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  // Inline-rename state: which row is open, plus the draft name/color for it.
  const [editing, setEditing] = useState<Editing>(null);
  const [draftName, setDraftName] = useState('');
  const [draftColor, setDraftColor] = useState(LABEL_COLORS[0]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError('');
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  };

  const addLabel = () => {
    const n = labelName.trim();
    if (!n) return;
    void run(async () => { await createLabel(n, labelColor); setLabelName(''); });
  };
  const addFolder = () => {
    const n = folderName.trim();
    if (!n) return;
    void run(async () => { await createFolder(n); setFolderName(''); });
  };

  const startEditLabel = (id: string, name: string, color: string) => {
    setEditing({ kind: 'label', id }); setDraftName(name); setDraftColor(color); setError('');
  };
  const startEditFolder = (id: string, name: string) => {
    setEditing({ kind: 'folder', id }); setDraftName(name); setError('');
  };
  const cancelEdit = () => setEditing(null);
  const saveEdit = () => {
    const n = draftName.trim();
    if (!editing || !n) return;
    const e = editing;
    void run(async () => {
      if (e.kind === 'label') await renameLabel(e.id, n, draftColor);
      else await renameFolder(e.id, n);
      setEditing(null);
    });
  };

  return (
    <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
      {error && (
        <div style={{ padding: 'var(--space-2) var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>{error}</div>
      )}

      {/* Two sections, not one nested in the other: a message carries any number of labels and sits
          in at most one folder, so neither is a kind of the other. */}
      <SettingsSection title="Labels">
        <div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
            A message can carry any number of labels. They show in the rail once you have one.
          </div>
          {labels.length === 0 && <div style={emptyStyle}>No labels yet.</div>}
          {labels.map(l => (
            editing?.kind === 'label' && editing.id === l.id ? (
              <div key={l.id} style={{ ...rowStyle, flexWrap: 'wrap' }}>
                <Input value={draftName} onChange={e => setDraftName(e.target.value)} placeholder="Label name" autoFocus
                  onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') cancelEdit(); }} style={{ flex: 1, minWidth: 140 }} />
                <ColorSwatches selected={draftColor} onPick={setDraftColor} />
                <IconButton size="sm" aria-label="Save label" disabled={busy || !draftName.trim()} onClick={saveEdit}><Icon name="check" size={15} /></IconButton>
                <IconButton size="sm" aria-label="Cancel rename" disabled={busy} onClick={cancelEdit}><Icon name="x" size={15} /></IconButton>
              </div>
            ) : (
              <div key={l.id} style={rowStyle}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: l.color, flex: 'none' }} />
                <span style={{ flex: 1, fontSize: 'var(--text-md)', color: 'var(--text-strong)' }}>{l.name}</span>
                <IconButton size="sm" aria-label={`Rename label ${l.name}`} disabled={busy} onClick={() => startEditLabel(l.id, l.name, l.color)}><Icon name="pencil" size={15} /></IconButton>
                <IconButton size="sm" aria-label={`Delete label ${l.name}`} disabled={busy} onClick={() => void run(() => deleteLabel(l.id))}><Icon name="trash" size={15} /></IconButton>
              </div>
            )
          ))}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
            <ColorSwatches selected={labelColor} onPick={setLabelColor} />
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-2)' }}>
            <Input value={labelName} onChange={e => setLabelName(e.target.value)} placeholder="New label name"
              onKeyDown={e => { if (e.key === 'Enter') addLabel(); }} style={{ flex: 1 }} />
            <Button variant="secondary" disabled={busy || !labelName.trim()} onClick={addLabel}>Add</Button>
          </div>
        </div>
      </SettingsSection>

      <SettingsSection title="Folders">
        <div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: 'var(--space-3)' }}>
            A message sits in one folder at a time. They show in the rail once you have one.
          </div>
          {folders.length === 0 && <div style={emptyStyle}>No folders yet.</div>}
          {folders.map(f => (
            editing?.kind === 'folder' && editing.id === f.id ? (
              <div key={f.id} style={rowStyle}>
                <Icon name="folder" size={15} style={{ color: 'var(--text-muted)', flex: 'none' }} />
                <Input value={draftName} onChange={e => setDraftName(e.target.value)} placeholder="Folder name" autoFocus
                  onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') cancelEdit(); }} style={{ flex: 1 }} />
                <IconButton size="sm" aria-label="Save folder" disabled={busy || !draftName.trim()} onClick={saveEdit}><Icon name="check" size={15} /></IconButton>
                <IconButton size="sm" aria-label="Cancel rename" disabled={busy} onClick={cancelEdit}><Icon name="x" size={15} /></IconButton>
              </div>
            ) : (
              <div key={f.id} style={rowStyle}>
                <Icon name="folder" size={15} style={{ color: 'var(--text-muted)', flex: 'none' }} />
                <span style={{ flex: 1, fontSize: 'var(--text-md)', color: 'var(--text-strong)' }}>{f.name}</span>
                <IconButton size="sm" aria-label={`Rename folder ${f.name}`} disabled={busy} onClick={() => startEditFolder(f.id, f.name)}><Icon name="pencil" size={15} /></IconButton>
                <IconButton size="sm" aria-label={`Delete folder ${f.name}`} disabled={busy} onClick={() => void run(() => deleteFolder(f.id))}><Icon name="trash" size={15} /></IconButton>
              </div>
            )
          ))}
          <div style={{ display: 'flex', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
            <Input value={folderName} onChange={e => setFolderName(e.target.value)} placeholder="New folder name"
              onKeyDown={e => { if (e.key === 'Enter') addFolder(); }} style={{ flex: 1 }} />
            <Button variant="secondary" disabled={busy || !folderName.trim()} onClick={addFolder}>Add</Button>
          </div>
        </div>
      </SettingsSection>
    </div>
  );
}
