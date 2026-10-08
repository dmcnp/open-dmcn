// Settings → Account → Export: the mailbox as files a person can take anywhere.
//
// One file per folder, each started by its own click: the save dialog has to be opened by a
// gesture, and an export of a large Inbox takes long enough that a second dialog opened at its
// end would no longer count as one. The work is done here, on this device, because only this
// device can open the mail (lib/export/).

import { useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from '../lib/hooks/useAuth';
import { useMessages } from '../lib/hooks/useMessages';
import { useSent } from '../lib/hooks/useSent';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import type { Preview } from '../lib/api/mailboxRest';
import { exportFolder, ExportStalled } from '../lib/export/exportFolder';
import { exportEntry, type MessageState } from '../lib/export/entry';
import { exportMessageId } from '../lib/export/mime';
import { exportFilename, openSink } from '../lib/export/sink';
import { formatBytes } from '../lib/format';
import { deployment } from '@deployment';
import { SettingsSection } from './SettingsSection';
import { Button, UsageMeter } from '../ds';
import { Icon } from './Icon';

type Folder = 'inbox' | 'sent';

type Run =
  | { kind: 'idle' }
  | { kind: 'running'; folder: Folder; done: number; total: number }
  | { kind: 'done'; folder: Folder; written: number; bytes: number; skipped: number; streaming: boolean }
  | { kind: 'cancelled'; folder: Folder }
  | { kind: 'failed'; folder: Folder; message: string };

const NAMES: Record<Folder, string> = { inbox: 'Inbox', sent: 'Sent' };

const textStyle = { margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' } as const;
const noteStyle = (tone: 'brand' | 'danger') => ({
  padding: 'var(--space-3)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)', lineHeight: 'var(--leading-normal)',
  background: tone === 'brand' ? 'var(--brand-subtle)' : 'var(--danger-subtle)',
  color: tone === 'brand' ? 'var(--brand-text)' : 'var(--danger)',
}) as const;

const count = (n: number) => `${n.toLocaleString()} ${n === 1 ? 'message' : 'messages'}`;

export function MailboxExport() {
  const { address } = useAuth();
  const { messages, loaded: inboxLoaded, accessState, openMessageFull } = useMessages();
  const { sent, loaded: sentLoaded, fetchSentFull } = useSent();
  const { isRead, isStarred, isArchived, labelsOf, folderOf } = useFlags();
  const { labelById, folderById } = useLabels();
  const [run, setRun] = useState<Run>({ kind: 'idle' });
  const abortRef = useRef<AbortController | null>(null);
  // Set the moment an export starts, before anything is awaited. `run` is React state and only
  // changes after the save dialog answers, so two quick taps would both find it idle.
  const busyRef = useRef(false);
  // The Message-ID each message is exported under, by DMCN message id, kept across both folders'
  // exports so a reply in Sent threads under a bridged parent the Inbox export already wrote.
  const idsRef = useRef(new Map<string, string>());

  // Control messages are the client talking to itself, not mail, and every folder leaves them out.
  const inbox = useMemo(() => {
    const control = new Set(deployment.controlSubjects);
    return messages.filter(m => !control.has(m.subject));
  }, [messages]);

  // The owner's state, read when each message is written so a label renamed meanwhile is current.
  const stateRef = useRef<(hash: string) => MessageState>(() => ({ read: false, starred: false, labels: [] }));
  stateRef.current = (hash: string) => {
    const folder = folderOf(hash);
    return {
      read: isRead(hash),
      starred: isStarred(hash),
      labels: labelsOf(hash).map(id => labelById(id)?.name ?? '').filter(Boolean),
      place: isArchived(hash) ? 'Archive' : folder ? folderById(folder)?.name : undefined,
    };
  };

  const running = run.kind === 'running';

  // Leaving the page ends the export, and the file with it: say so before it happens.
  useEffect(() => {
    if (!running) return;
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault(); };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [running]);
  useEffect(() => () => abortRef.current?.abort(), []);

  const start = async (folder: Folder) => {
    if (!address || busyRef.current) return;
    busyRef.current = true;
    try {
      await runExport(folder, address);
    } finally {
      busyRef.current = false;
    }
  };

  const runExport = async (folder: Folder, address: string) => {
    // Straight from the click, before anything else is awaited: the save dialog needs the gesture.
    const sink = await openSink(exportFilename(address, folder));
    if (!sink) return;
    const rows: Preview[] = [...(folder === 'inbox' ? inbox : sent)].sort((a, b) => a.sentAt - b.sentAt);
    // Every message's Message-ID as a native one is exported (a bridged one replaces its own with
    // the original's when it is written), so a reply names its parent the way the file does.
    const ids = idsRef.current;
    for (const m of [...inbox, ...sent]) {
      const id = m.messageId.toLowerCase();
      if (m.messageId && !ids.has(id)) ids.set(id, exportMessageId(id, m.senderAddress));
    }
    const open = folder === 'inbox' ? openMessageFull : fetchSentFull;
    const abort = new AbortController();
    abortRef.current = abort;
    setRun({ kind: 'running', folder, done: 0, total: rows.length });
    try {
      const res = await exportFolder({
        items: rows,
        load: row => exportEntry(row, open, folder === 'sent', h => stateRef.current(h), ids),
        write: b => sink.write(b),
        signal: abort.signal,
        onProgress: (done, total) => setRun({ kind: 'running', folder, done, total }),
      });
      await sink.close();
      setRun({ kind: 'done', folder, written: res.written, bytes: res.bytes, skipped: res.skipped.length, streaming: sink.streaming });
    } catch (err) {
      await sink.abort();
      if (err instanceof DOMException && err.name === 'AbortError') {
        setRun({ kind: 'cancelled', folder });
      } else {
        console.error('export failed', err);
        setRun({
          kind: 'failed', folder,
          message: err instanceof ExportStalled
            ? 'The export stopped because several messages in a row could not be loaded. Check your connection and try again.'
            : `The export stopped: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    } finally {
      if (abortRef.current === abort) abortRef.current = null;
    }
  };

  const closed = accessState === 'closed' || accessState === 'unapproved-device';
  const ready = { inbox: inboxLoaded, sent: sentLoaded };
  const sizes = { inbox: inbox.length, sent: sent.length };

  return (
    <SettingsSection title="Export">
      <p style={textStyle}>
        Download a copy of your mail as standard mbox files, one for the Inbox and one for Sent. Apple Mail imports
        them directly, and Thunderbird with its free ImportExportTools NG add-on. Your mail is decrypted on this
        device to make the files, so they are not encrypted: keep them somewhere only you can reach.
      </p>

      {closed ? (
        <p style={textStyle}>This mailbox cannot be opened from here, so there is nothing to export.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {(['inbox', 'sent'] as const).map(folder => (
            <div key={folder} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 160 }}>
                <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>{NAMES[folder]}</div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2 }}>
                  {ready[folder] ? count(sizes[folder]) : 'Loading…'}
                </div>
              </div>
              <Button
                size="sm" variant="secondary"
                leftIcon={<Icon name="download" size={15} />}
                disabled={running || !ready[folder] || sizes[folder] === 0}
                onClick={() => void start(folder)}
                data-testid={`export-${folder}`}
              >
                Export {NAMES[folder]}
              </Button>
            </div>
          ))}
        </div>
      )}

      {run.kind === 'running' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          <UsageMeter
            label={`Exporting ${NAMES[run.folder]}`}
            value={run.done} max={Math.max(run.total, 1)} variant="brand"
            valueText={`${run.done.toLocaleString()} of ${run.total.toLocaleString()}`}
          />
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <span style={{ ...textStyle, flex: 1 }}>Keep this page open until it finishes. Leaving it stops the export.</span>
            <Button size="sm" variant="secondary" onClick={() => abortRef.current?.abort()}>Cancel</Button>
          </div>
        </div>
      )}
      {run.kind === 'done' && (
        <div style={noteStyle('brand')} role="status" data-testid="export-result">
          {NAMES[run.folder]}: {count(run.written)} exported ({formatBytes(run.bytes)}).
          {!run.streaming && ' Your browser is saving the file to your downloads.'}
          {run.skipped > 0 && ` ${count(run.skipped)} could not be loaded and ${run.skipped === 1 ? 'was' : 'were'} left out. Export again later to include ${run.skipped === 1 ? 'it' : 'them'}.`}
        </div>
      )}
      {run.kind === 'cancelled' && (
        <div style={textStyle} role="status">Export of {NAMES[run.folder]} cancelled. Nothing was saved.</div>
      )}
      {run.kind === 'failed' && (
        <div style={noteStyle('danger')} role="alert">{run.message} Nothing was saved.</div>
      )}
    </SettingsSection>
  );
}
