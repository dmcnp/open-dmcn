import { useEffect, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { useOutletContext } from 'react-router-dom';
import { useMessages, type Preview } from '../lib/hooks/useMessages';
import { useSent, isSentStoreHash } from '../lib/hooks/useSent';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import { useAuth } from '../lib/hooks/useAuth';
import { useContacts } from '../lib/hooks/useContacts';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { categorizeSender } from '../lib/trust/category';
import { isReceivedForMe, previewText } from '../lib/mailView';
import { useIsMobile } from '../lib/useIsMobile';
import { IconButton } from '../ds';
import { Icon } from '../components/Icon';
import { KindIcon } from '../components/KindIcon';
import { useCounterpartyKind } from '../lib/hooks/useCounterpartyKind';
import { senderLabel } from '../lib/trust/displayName';
import { MessageReader } from '../components/MessageReader';
import type { ComposeReplyTo } from '../lib/compose';
import type { MailOutletContext } from '../components/AppLayout';
import { deployment } from '@deployment';
import { formatWhen } from '../lib/format';

// Control messages this deployment carries (device pairing, countersign requests) are
// surfaced in their own panels, not the normal mail folders. Empty on a deployment whose
// protocol has none, which leaves every message ordinary mail.
// A function, not a module-level Set: `deployment` imports screens that import this module,
// and a value read during module evaluation would depend on which side of that cycle ran first.
const controlSubjects = () => new Set<string>(deployment.controlSubjects);

// A displayed row: one Preview plus every mailbox hash it stands for. Normally one
// hash, but Sent rows fold all copies sharing a messageId together (a defensive
// merge — a multi-recipient send already writes a single self-copy, but this also
// collapses any duplicate/legacy per-recipient copies) so deleting a row removes
// all of them.
interface Row { msg: Preview; hashes: string[] }

function groupSent(previews: Preview[]): Row[] {
  const byKey = new Map<string, Row>();
  for (const m of previews) {
    const key = m.messageId || m.hash; // pre-feature copies have no messageId → never merge
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { msg: m, hashes: [m.hash] });
      continue;
    }
    existing.hashes.push(m.hash);
    // Keep the newest copy as the representative, but union the recipient lists so
    // the "To:" label reflects everyone the message went to.
    const base = m.sentAt > existing.msg.sentAt ? m : existing.msg;
    existing.msg = {
      ...base,
      to: [...new Set([...existing.msg.to, ...m.to])],
      cc: [...new Set([...existing.msg.cc, ...m.cc])],
    };
  }
  return [...byKey.values()];
}

// --- message row (desktop one-line w/ hover delete; mobile two-line w/ swipe) ---

const SWIPE_W = 176; // px revealed by swiping a row left on mobile (Archive + Delete)

function MailRow({ msg, sent, unknownSender, mobile, hovered, read, starred, inArchive, nameFor, onOpen, onDelete, onArchive, onToggleStar, onHover }: {
  msg: Preview; sent: boolean; unknownSender?: boolean; mobile: boolean; hovered: boolean;
  read: boolean; starred: boolean; inArchive: boolean; nameFor: (address: string) => string;
  onOpen: () => void; onDelete: () => void; onArchive: () => void; onToggleStar: () => void; onHover: (h: boolean) => void;
}) {
  // Unread applies to received mail only (you don't "read" your own Sent copy).
  const unread = !sent && !read;
  // Informational hint: this sender isn't in your contacts/allowlist yet. Purely a glanceable cue
  // now that Inbox and Pending are one list — it grants NO access (the reader gates at read time),
  // so it's fine that it's cheap and address-based.
  const newSenderTag = unknownSender ? (
    <span title="Sender isn't in your contacts yet" style={{
      flex: 'none', alignSelf: 'center', fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.02em',
      textTransform: 'uppercase', color: 'var(--text-muted)', background: 'var(--surface-sunken)',
      border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '0 5px', lineHeight: '15px',
    }}>New</span>
  ) : null;
  const nameWeight = unread ? 700 : 500;
  // The cleaned preview decides everything about the snippet: whether it renders, and how the
  // subject is sized — so the two can never disagree about how many columns the middle of the
  // row holds. Cleaning first matters: bulk mail routinely opens with "[image: Logo][1]", which
  // previewText reduces to nothing, and an empty preview must not claim a column or leave a
  // dangling em-dash behind.
  const preview = msg.snippet && !unknownSender ? previewText(msg.snippet) : '';
  const showSnippet = preview !== '';
  // For a sent message the "who" is the full recipient audience (To + Cc). Falls back
  // to the singular recipientAddress for pre-feature messages with no lists. Every
  // recipient address goes through nameFor, so a contact shows under the name its owner gave it.
  const recipientList = msg.to.length || msg.cc.length ? [...msg.to, ...msg.cc] : [msg.recipientAddress];
  const whoAddress = sent ? recipientList[0] : msg.senderAddress;
  // Owner-given contact name first, then the display name the message carried (legacy
  // mail's From name), then the address. The row is a scanning surface with one narrow
  // column, so a sender-supplied name appears here without the address next to it — the
  // address is one hover (title) away, the "New" tag flags a sender you don't know, and
  // the reader, where trusting actually happens, always shows name AND address.
  const who = senderLabel(whoAddress, nameFor(whoAddress), sent ? '' : msg.senderDisplay).primary;
  const sentLabel = `To: ${recipientList.map(nameFor).join(', ')}`;
  // Who this row is about — the sender, or the first recipient in Sent. For received
  // mail the header's signing key is compared against the directory, so a bridged
  // message claiming a DMCN address can't wear the shield.
  const kind = useCounterpartyKind(whoAddress, sent ? '' : msg.senderPublicKey);
  const [dx, setDx] = useState(0);
  const drag = useRef({ x: 0, y: 0, active: false, decided: null as null | 'h' | 'v', startDx: 0, moved: false });

  if (mobile) {
    const onDown = (e: React.PointerEvent) => { drag.current = { x: e.clientX, y: e.clientY, active: true, decided: null, startDx: dx, moved: false }; };
    const onMove = (e: React.PointerEvent) => {
      const d = drag.current; if (!d.active) return;
      const ddx = e.clientX - d.x, ddy = e.clientY - d.y;
      if (d.decided === null && (Math.abs(ddx) > 8 || Math.abs(ddy) > 8)) {
        d.decided = Math.abs(ddx) > Math.abs(ddy) ? 'h' : 'v';
        if (d.decided === 'h') { try { (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId); } catch { /* ignore */ } }
      }
      if (d.decided === 'h') { d.moved = true; setDx(Math.max(-SWIPE_W, Math.min(0, d.startDx + ddx))); }
    };
    const onUp = () => {
      const d = drag.current; d.active = false;
      if (d.decided !== 'h' && !d.moved) { if (dx < 0) setDx(0); else onOpen(); return; }
      if (d.decided === 'h') setDx(dx <= -SWIPE_W / 2 ? -SWIPE_W : 0);
    };
    return (
      <div style={{ position: 'relative', borderBottom: '1px solid var(--border-subtle)', overflow: 'hidden', background: 'var(--surface-page)' }}>
        {/* action layer revealed by swiping left */}
        <div style={{ position: 'absolute', top: 0, right: 0, bottom: 0, width: SWIPE_W, display: 'flex' }}>
          {!sent && (
            <button aria-label={inArchive ? 'Unarchive' : 'Archive'} onClick={() => { setDx(0); onArchive(); }}
              style={{ flex: 1, border: 'none', cursor: 'pointer', background: 'var(--surface-hover)', color: 'var(--text-strong)', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4, font: 'inherit', fontSize: 'var(--text-2xs)' }}>
              <Icon name="archive" size={20} /> {inArchive ? 'Unarchive' : 'Archive'}
            </button>
          )}
          <button aria-label="Delete" onClick={() => { setDx(0); onDelete(); }}
            style={{ flex: 1, border: 'none', cursor: 'pointer', background: 'var(--danger)', color: '#fff', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4, font: 'inherit', fontSize: 'var(--text-2xs)' }}>
            <Icon name="trash" size={20} /> Delete
          </button>
        </div>
        <div
          onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp}
          onPointerCancel={() => { drag.current.active = false; setDx(dx <= -SWIPE_W / 2 ? -SWIPE_W : 0); }}
          style={{
            position: 'relative', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)', cursor: 'pointer',
            padding: 'var(--space-3) var(--space-4)', touchAction: 'pan-y',
            transform: `translateX(${dx}px)`, transition: drag.current.active ? 'none' : 'transform var(--dur-normal) var(--ease-out)',
            background: 'var(--surface-card)', borderLeft: '2px solid transparent',
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
              {unread && <span style={{ flex: 'none', width: 8, height: 8, borderRadius: '50%', background: 'var(--brand)', alignSelf: 'center' }} />}
              <span style={{ alignSelf: 'center', display: 'inline-flex', marginRight: 2 }}><KindIcon kind={kind} size={14} /></span>
              <span title={sent ? recipientList.join(', ') : who === whoAddress ? whoAddress : `${who} <${whoAddress}>`} style={{ flex: 1, minWidth: 0, fontSize: 'var(--text-md)', color: 'var(--text-strong)', fontWeight: nameWeight, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {sent ? sentLabel : who}
              </span>
              {newSenderTag}
              {starred && <Icon name="star-fill" size={14} style={{ color: 'var(--warning)', flex: 'none' }} />}
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', flex: 'none' }}>{formatWhen(msg.sentAt)}</span>
            </div>
            <div style={{ marginTop: 2, fontSize: 'var(--text-md)', color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{msg.subject || '(no subject)'}</div>
          {/* The snippet is body text — the leading 140 bytes of it (SPEC.md) — so it is
              withheld on exactly the terms the body is. An unknown sender's body is already
              hidden behind the reveal gate at read time; showing their snippet here would put
              a line of their own words in front of the owner while they are still deciding
              whether to trust them, which is the thing that gate exists to prevent. The check
              is address-based and therefore spoofable: it stops an unknown sender, not a
              targeted spoof of a known one, which the reader catches on open. */}
            {showSnippet && <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{preview}</div>}
          </div>
        </div>
      </div>
    );
  }

  const rowBg: CSSProperties['background'] = hovered ? 'var(--surface-hover)' : 'var(--surface-card)';
  return (
    <div
      onClick={onOpen}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 'var(--space-3)', cursor: 'pointer',
        padding: 'var(--density-row) var(--space-4)', background: rowBg,
        borderBottom: '1px solid var(--border-subtle)', borderLeft: '2px solid transparent',
      }}
    >
      <span style={{ flex: 'none', width: 8, height: 8, borderRadius: '50%', background: unread ? 'var(--brand)' : 'transparent' }} />
      {/* The star lives here, always rendered in both states: it gives the row a
          constant height (an icon button is taller than the text line), so hovering
          reveals actions without the row growing or the columns shifting. */}
      <IconButton size="sm" aria-label={starred ? 'Unstar' : 'Star'} onClick={e => { e.stopPropagation(); onToggleStar(); }}>
        <Icon name={starred ? 'star-fill' : 'star'} size={16} style={starred ? { color: 'var(--warning)' } : undefined} />
      </IconButton>
      {/* The kind icon describes the PERSON, so it sits with their name; the star
          describes the message but lives in the left rail with it (where mail clients
          put it) rather than floating in the middle of the subject text. */}
      <div style={{ minWidth: 180, width: 180, flex: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
        <KindIcon kind={kind} size={14} />
        <span title={sent ? recipientList.join(', ') : who === whoAddress ? whoAddress : `${who} <${whoAddress}>`} style={{ minWidth: 0, fontSize: 'var(--text-md)', color: 'var(--text-strong)', fontWeight: nameWeight, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {sent ? `To: ${who}` : who}
        </span>
        {newSenderTag}
      </div>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
        {/* The 45% cap exists to leave room for the snippet beside it. With no snippet there
            is no second column to leave room for, so the subject takes the whole middle and
            truncates only when it genuinely overruns — `0 1 auto` + minWidth:0 so it still
            shrinks against the date column rather than pushing through it. */}
        <span style={{ fontSize: 'var(--text-md)', color: 'var(--text-strong)', fontWeight: unread ? 600 : 400, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', ...(showSnippet ? { flex: 'none', maxWidth: '45%' } : { flex: '0 1 auto', minWidth: 0 }) }}>
          {msg.subject || '(no subject)'}
        </span>
        {showSnippet && (
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
            &mdash; {preview}
          </span>
        )}
      </div>
      <div style={{ flex: 'none', width: 140, display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 'var(--space-2)' }}>
        {/* The date never moves or disappears, and the hover actions keep their slot
            when hidden (visibility, not unmounting) — so hovering changes colours,
            never geometry. */}
        <span style={{ flex: 1, textAlign: 'right', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatWhen(msg.sentAt)}</span>
        <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: 2, visibility: hovered ? 'visible' : 'hidden' }}>
          {!sent && (
            <IconButton size="sm" aria-label={inArchive ? 'Unarchive' : 'Archive'} onClick={e => { e.stopPropagation(); onArchive(); }}><Icon name="archive" size={16} /></IconButton>
          )}
          <IconButton size="sm" aria-label="Delete" onClick={e => { e.stopPropagation(); onDelete(); }}><Icon name="trash" size={16} /></IconButton>
        </div>
      </div>
    </div>
  );
}

/** The mail content (list + reader) that fills the app shell's main column. */
export function InboxMain() {
  const { messages, error, refresh, deleteMessage } = useMessages();
  const { sent, error: sentError, refreshSent, fetchSentFull, deleteSent } = useSent();
  const { isRead, isArchived, isStarred, setFlag, markRead, labelsOf, folderOf, removeFlags } = useFlags();
  const { knownFolderIds, labelById, folderById } = useLabels();
  const { address } = useAuth();
  const { contactByAddress, nameFor } = useContacts();
  const { filter: mailFilter } = useMailFilter();
  const isMobile = useIsMobile();
  const { folder, filter, openCompose } = useOutletContext<MailOutletContext>();

  const [hovered, setHovered] = useState<string | null>(null);
  const [openHash, setOpenHash] = useState<string | null>(null);

  // Close an open message when the folder changes.
  useEffect(() => { setOpenHash(null); }, [folder]);

  const isSent = (sender: string) => address != null && sender === address;
  const control = controlSubjects();
  const mail = messages.filter(m => !control.has(m.subject));
  // Address-based sender category (cheap, no body fetch). Used ONLY for the optional "Unknown
  // senders" filter and the informational per-row hint — it does NOT decide Inbox membership.
  // Trust is enforced at read time by the reader's gate (which can run the real native-key /
  // bridge-SPF-DKIM-DMARC checks), so a spoofable address match here carries no trust weight.
  const catOf = (m: Preview): 'allowlisted' | 'pending' | 'blocked' =>
    isSent(m.senderAddress) ? 'allowlisted' : categorizeSender(m.senderAddress, m.senderPublicKey, contactByAddress(m.senderAddress), mailFilter);

  const q = filter.trim().toLowerCase();
  const matchesQ = (m: Preview) =>
    !q || `${m.senderAddress} ${m.recipientAddress} ${[...m.to, ...m.cc].join(' ')} ${m.subject} ${m.snippet}`.toLowerCase().includes(q);

  let rows: Row[];
  if (folder === 'sent') {
    // Sent reads from the personal store; also fold in any legacy self-copies still
    // in the mailbox (deduped by messageId) so nothing is lost on upgrade.
    const storeMsgIds = new Set(sent.map(p => p.messageId));
    const legacySent = mail.filter(m => isSent(m.senderAddress) && (!m.messageId || !storeMsgIds.has(m.messageId)));
    const storeRows: Row[] = sent.filter(matchesQ).map(p => ({ msg: p, hashes: [p.hash] }));
    const legacyRows = groupSent(legacySent.filter(matchesQ));
    rows = [...storeRows, ...legacyRows].sort((a, b) => b.msg.sentAt - a.msg.sentAt);
  } else {
    // Received mail, split by flag/label/folder. Inbox = not archived and not filed
    // into a known folder; Archive/Starred are flag views; label:/folder: are the
    // user's own collections (an intrinsic view over messages ∪ flags ∪ definitions).
    const labelSel = folder.startsWith('label:') ? folder.slice('label:'.length) : null;
    const folderSel = folder.startsWith('folder:') ? folder.slice('folder:'.length) : null;
    // A message is "filed" only if its folderId names a folder that still exists —
    // so deleting a folder returns its messages to the Inbox with no flag cleanup.
    const isFiled = (h: string) => { const f = folderOf(h); return !!f && knownFolderIds.has(f); };
    const inFolder = (m: Preview) => {
      // A message I sent is a Sent item, hidden from received views — unless I'm also
      // a recipient (I mailed myself), where this mailbox copy is genuine received mail.
      if (!isReceivedForMe(m, address)) return false;
      if (labelSel) return labelsOf(m.hash).includes(labelSel);
      if (folderSel) return folderOf(m.hash) === folderSel;
      if (folder === 'archive') return isArchived(m.hash);
      if (folder === 'starred') return isStarred(m.hash);
      // One combined inbox: every received message except blocked senders (still hidden) and
      // archived/filed ones. There is no trust-based list split — trust is decided at READ TIME by
      // the reader's gate, so a spoofed sender can't ride an address match into a "trusted" bucket.
      return catOf(m) !== 'blocked' && !isArchived(m.hash) && !isFiled(m.hash);
    };
    rows = mail.filter(inFolder).filter(matchesQ).map(m => ({ msg: m, hashes: [m.hash] }));
  }

  // Delete routes each hash to its source: a "sent:" hash is a personal-store record,
  // everything else is a mailbox message.
  const doDelete = async (hashes: string[]) => {
    for (const hash of hashes) {
      try {
        if (isSentStoreHash(hash)) await deleteSent(hash);
        else { await deleteMessage(hash); await removeFlags(hash); } // GC the message's flag record
      } catch { /* ignore */ }
    }
  };

  // The open message is resolved against the full source (mailbox or Sent store) so
  // it survives filter changes while the reader is open.
  const openMsg = openHash
    ? (isSentStoreHash(openHash) ? sent.find(p => p.hash === openHash) : mail.find(m => m.hash === openHash)) ?? null
    : null;

  // Opening a received message marks it read (Sent copies are never "unread").
  const openRow = (m: Preview) => {
    setOpenHash(m.hash);
    if (!isSentStoreHash(m.hash) && isReceivedForMe(m, address)) void markRead(m.hash);
  };
  const toggleArchive = (m: Preview) => setFlag(m.hash, { archived: !isArchived(m.hash) });
  const toggleStar = (m: Preview) => setFlag(m.hash, { starred: !isStarred(m.hash) });

  const handleReply = (replyTo: ComposeReplyTo) => {
    setOpenHash(null);
    openCompose(replyTo);
  };

  const pending = !!error && error.includes('POLICY_PENDING');
  const listError = folder === 'sent' ? sentError : error;
  const doRefresh = () => { refresh(); refreshSent(); };
  const showFab = isMobile && !openMsg;

  const folderTitle = folder.startsWith('label:') ? (labelById(folder.slice(6))?.name ?? 'Label')
    : folder.startsWith('folder:') ? (folderById(folder.slice(7))?.name ?? 'Folder')
    : folder === 'sent' ? 'Sent' : folder === 'archive' ? 'Archive' : folder === 'starred' ? 'Starred'
    : 'Inbox';
  const emptyText = folder === 'sent' ? 'Nothing sent yet.'
    : folder === 'archive' ? 'Nothing archived.'
    : folder === 'starred' ? 'No starred messages.'
    : folder.startsWith('label:') ? 'No messages with this label.'
    : folder.startsWith('folder:') ? 'This folder is empty.'
    : "You're all caught up. Nothing else to read.";

  return (
    <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
      {openMsg ? (
        <MessageReader
          msg={openMsg}
          sentView={folder === 'sent'}
          onBack={() => setOpenHash(null)}
          onReply={handleReply}
          mobile={isMobile}
          openFull={isSentStoreHash(openMsg.hash) ? fetchSentFull : undefined}
          onDeleteOverride={isSentStoreHash(openMsg.hash) ? () => deleteSent(openMsg.hash) : undefined}
          starred={isStarred(openMsg.hash)}
          archived={isArchived(openMsg.hash)}
          onToggleStar={() => toggleStar(openMsg)}
          onArchive={folder !== 'sent' && isReceivedForMe(openMsg, address) ? () => { void toggleArchive(openMsg); setOpenHash(null); } : undefined}
        />
      ) : (
        <>
          {/* List header */}
          <div style={{
            padding: 'var(--space-3) var(--space-4)', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)',
          }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
              <span style={{ fontSize: 'var(--text-lg)', fontWeight: 600, letterSpacing: 'var(--tracking-tight)', color: 'var(--text-strong)' }}>
                {q ? 'Filter results' : folderTitle}
              </span>
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                {rows.length} {rows.length === 1 ? 'message' : 'messages'}
              </span>
            </div>
            <IconButton size="sm" aria-label="Refresh" onClick={doRefresh}><Icon name="refresh" size={16} /></IconButton>
          </div>

          {/* List body */}
          <div style={{ overflowY: 'auto', flex: 1, background: 'var(--surface-page)' }}>
            {pending && (
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', margin: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>
                <Icon name="alert-triangle" size={16} style={{ color: 'var(--warning)', marginTop: 1 }} />
                <span>Your address is awaiting approval by the domain administrator. Your mailbox will be available once it's countersigned.</span>
              </div>
            )}
            {!pending && listError && (
              <div style={{ margin: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', borderRadius: 'var(--radius-md)', fontSize: 'var(--text-sm)' }}>{listError}</div>
            )}

            {rows.length === 0 ? (
              <div style={{ padding: 'var(--space-16) var(--space-4)', textAlign: 'center', color: 'var(--text-muted)' }}>
                <Icon name={q ? 'search' : folder === 'archive' ? 'archive' : folder === 'starred' ? 'star' : 'inbox'} size={28} style={{ color: 'var(--text-subtle)', margin: '0 auto' }} />
                <p style={{ marginTop: 'var(--space-3)', fontSize: 'var(--text-base)' }}>
                  {q ? 'No messages match your filter.' : emptyText}
                </p>
              </div>
            ) : (
              rows.map(({ msg, hashes }) => (
                <MailRow
                  key={msg.hash}
                  msg={msg}
                  sent={folder === 'sent'}
                  unknownSender={folder !== 'sent' && catOf(msg) === 'pending'}
                  mobile={isMobile}
                  hovered={hovered === msg.hash}
                  read={isRead(msg.hash)}
                  starred={isStarred(msg.hash)}
                  inArchive={folder === 'archive'}
                  nameFor={nameFor}
                  onOpen={() => openRow(msg)}
                  onDelete={() => doDelete(hashes)}
                  onArchive={() => toggleArchive(msg)}
                  onToggleStar={() => toggleStar(msg)}
                  onHover={h => setHovered(h ? msg.hash : null)}
                />
              ))
            )}
          </div>
        </>
      )}

      {showFab && (
        <button aria-label="Compose" onClick={() => openCompose(null)} style={{
          position: 'absolute', right: 'calc(var(--space-5) + env(safe-area-inset-right))',
          bottom: 'calc(var(--space-5) + env(safe-area-inset-bottom))', width: 56, height: 56,
          border: 'none', background: 'var(--brand)', color: 'var(--text-onbrand)', cursor: 'pointer',
          boxShadow: 'var(--shadow-md)', display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 35, borderRadius: 'var(--radius-md)',
        }}>
          <Icon name="pencil" size={22} />
        </button>
      )}
    </div>
  );
}
