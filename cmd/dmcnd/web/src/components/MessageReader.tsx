import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { Preview, FullBody } from '../lib/api/mailboxRest';
import { useMessages } from '../lib/hooks/useMessages';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import type { LabelDef } from '../lib/api/labelStore';
import { useAuth } from '../lib/hooks/useAuth';
import { Badge, Button, IconButton, Tag } from '../ds';
import { Icon } from './Icon';
import { lookupIdentity } from '../lib/api/client';
import { verifyBridgeAttestation, BridgeTrustTier, CLASSIFICATION_CONTENT_TYPE, type BridgeAttestation } from '../lib/crypto/bridgeAttest';
import { verifyDeliveryReceipt, RECEIPT_CONTENT_TYPE, type DeliveryReceiptView } from '../lib/crypto/receiptAttest';
import { evaluateSenderTrust, type SenderTrust } from '../lib/crypto/senderTrust';
import { senderTrustView } from '../lib/trust/trustView';
import { useContacts } from '../lib/hooks/useContacts';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { categorizeSender } from '../lib/trust/category';
import type { DecryptedAttachment } from '../lib/crypto/split';
import { HtmlMessageBody } from './HtmlMessageBody';
import type { ComposeReplyTo } from './ComposeDialog';
import { sanitizeOutgoing } from '../lib/html/sanitize';
import { fromPlainText, escapeHtml } from '../lib/html/fromPlainText';
import { directoryFacts } from '../lib/trust/pinnedKey';
import { fromHex } from '../lib/crypto/keys';

// attestationView maps a bridged-message verdict to its display treatment. Only a
// verified verdict shows the bridge-asserted trust tier; an unverified verdict is
// always a warning, regardless of the (untrusted) tier it claims.
function attestationView(a: BridgeAttestation): {
  variant: 'success' | 'warning' | 'danger';
  icon: 'shield-check' | 'alert-triangle';
  label: string;
  detail: string;
} {
  if (!a.verified) {
    return {
      variant: 'danger',
      icon: 'alert-triangle',
      label: 'Unverified bridge',
      detail: `This message arrived via an SMTP bridge that could not be verified${a.reason ? ` (${a.reason})` : ''}. Treat its sender with caution.`,
    };
  }
  const who = a.smtpFrom || 'the sender';
  // No separate "is the bridge itself anchored?" note any more. Reaching this point already means
  // the bridge holds a credential signed by its domain's root — there is no half-trusted state
  // left to caveat, and the old note invited readers to weigh something already decided.
  switch (a.trustTier) {
    case BridgeTrustTier.VerifiedLegacy:
      return { variant: 'success', icon: 'shield-check', label: 'Verified legacy sender', detail: `A verified bridge confirmed SPF/DKIM/DMARC for ${who}.` };
    case BridgeTrustTier.Suspicious:
      return { variant: 'danger', icon: 'alert-triangle', label: 'Suspicious legacy sender', detail: `Legacy authentication failed for ${who} — this sender may be forged.` };
    default:
      return { variant: 'warning', icon: 'alert-triangle', label: 'Unverified legacy sender', detail: `${who}'s domain did not fully authenticate this message.` };
  }
}

// Minimal themed style for the native label/folder assignment selects.
const assignSelectStyle: CSSProperties = {
  font: 'inherit', fontSize: 'var(--text-sm)', color: 'var(--text-body)',
  background: 'var(--surface-card)', border: '1px solid var(--border-default)',
  borderRadius: 'var(--radius-sm)', padding: '3px 8px', cursor: 'pointer',
};

function formatDate(sec: number): string {
  return new Date(sec * 1000).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
}
function formatTime(sec: number): string {
  return new Date(sec * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

// receiptView maps a delivery-receipt verdict to its display treatment: a verified receipt shows
// the bridge's delivered/failed outcome; an unverified one is a warning.
function receiptView(r: DeliveryReceiptView): {
  variant: 'success' | 'warning' | 'danger';
  icon: 'shield-check' | 'alert-triangle';
  label: string;
  detail: string;
} {
  if (!r.verified) {
    return {
      variant: 'warning',
      icon: 'alert-triangle',
      label: 'Unverified receipt',
      detail: `This delivery receipt could not be verified${r.reason ? ` (${r.reason})` : ''}.`,
    };
  }
  const who = r.recipientEmail || 'the recipient';
  if (r.delivered) {
    return { variant: 'success', icon: 'shield-check', label: 'Delivered', detail: `The bridge delivered your message to ${who}.` };
  }
  return { variant: 'danger', icon: 'alert-triangle', label: 'Delivery failed', detail: `The bridge could not deliver your message to ${who}${r.errorDetail ? `: ${r.errorDetail}` : ''}.` };
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// System attachments carried for protocol purposes (the bridge attestation and the raw
// legacy source) are consumed elsewhere and hidden from the user-facing list.
const INTERNAL_ATTACHMENT_TYPES = new Set<string>([
  CLASSIFICATION_CONTENT_TYPE,
  RECEIPT_CONTENT_TYPE,
  'message/rfc822', // original.eml — raw legacy email preserved by the bridge
]);
function userAttachments(all: DecryptedAttachment[]): DecryptedAttachment[] {
  return all.filter(a => !INTERNAL_ATTACHMENT_TYPES.has(a.contentType));
}

// sanitizeFilename strips path separators, control chars, and leading dots before the
// name is used as a download target, so a hostile filename can't escape the download
// dir or masquerade (the browser's `download` attribute already forces save-to-disk).
function sanitizeFilename(name: string): string {
  const clean = (name || '')
    .replace(/[/\\]/g, '_')
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, '')
    .replace(/^\.+/, '')
    .trim()
    .slice(0, 200);
  return clean || 'attachment';
}

// downloadAttachment saves an attachment via a transient blob: URL. The blob is revoked
// on a delay so the bytes aren't retained; nothing is opened inline, so a hostile
// content type can't execute in-page.
function downloadAttachment(a: DecryptedAttachment): void {
  const blob = new Blob([a.content as BufferSource], { type: a.contentType || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = sanitizeFilename(a.filename);
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export interface MessageReaderProps {
  msg: Preview;
  sentView: boolean;
  onBack: () => void;
  onReply: (replyTo: ComposeReplyTo) => void;
  /** Tighter padding + smaller title on mobile. */
  mobile?: boolean;
  /** Overrides the mailbox body fetch — used for Sent messages, which read their
   *  self-sealed envelope from the personal store instead of the mailbox. Same
   *  FullBody shape, so the render path (body, attachments, HTML) is identical. */
  openFull?: (hash: string) => Promise<FullBody>;
  /** Overrides the default mailbox delete (e.g. delete a Sent record from the store). */
  onDeleteOverride?: () => Promise<void>;
  /** Flag state + toggles (extrinsic metadata). onArchive omitted ⇒ archive hidden. */
  starred?: boolean;
  archived?: boolean;
  onToggleStar?: () => void;
  onArchive?: () => void;
}

/**
 * In-page email detail view. Renders in place of the message list (the design's
 * Reader pattern) rather than as a standalone route, so the inbox shell stays put.
 */
export function MessageReader({ msg, sentView, onBack, onReply, mobile = false, openFull, onDeleteOverride, starred, archived, onToggleStar, onArchive }: MessageReaderProps) {
  const { openMessageFull, deleteMessage } = useMessages();
  const { labelsOf, folderOf, addLabel, removeLabel, setFolder, removeFlags } = useFlags();
  const { labels, folders, labelById } = useLabels();
  const { address } = useAuth();
  const { contactByAddress, nameFor, allowlist, pinKey, ready: contactsReady } = useContacts();
  const { filter: mailFilter, blockSender, ready: filterReady } = useMailFilter();

  // Extrinsic assignment for this message (labels are many; folder is single).
  const appliedLabelIds = labelsOf(msg.hash);
  const appliedLabels = appliedLabelIds.map(id => labelById(id)).filter((l): l is LabelDef => !!l);
  const availableLabels = labels.filter(l => !appliedLabelIds.includes(l.id));
  const currentFolder = folderOf(msg.hash);

  // A message I authored (my own address). True for Sent copies and for a message I
  // mailed to myself now shown as received — either way it's inherently trusted, so
  // the pending-sender gate and native-trust resolution below never apply to it.
  const sentByMe = address != null && msg.senderAddress.toLowerCase() === address.toLowerCase();
  const ownMessage = sentView || sentByMe;

  // Sent messages read their self-sealed envelope from the personal store; everything
  // else fetches from the mailbox. Both return the same FullBody, so one code path.
  const fetchFull = openFull ?? openMessageFull;
  const [body, setBody] = useState<string | null>(null);
  const [bodyError, setBodyError] = useState<string | null>(null);
  // The text/html rendering, when the message carries one. It renders only for a
  // trusted sender (see htmlAllowed) — a pending sender's plain-text peek never
  // renders HTML. `showHtml` toggles between the two views.
  const [htmlBody, setHtmlBody] = useState<string | null>(null);
  const [showHtml, setShowHtml] = useState(true);
  const [attachments, setAttachments] = useState<DecryptedAttachment[]>([]);
  // Per-file "download anyway" acknowledgments for a sender who isn't trusted yet.
  const [ackedDownloads, setAckedDownloads] = useState<Set<number>>(new Set());
  const [attestation, setAttestation] = useState<BridgeAttestation | null>(null);
  // A bridge delivery receipt for a message I sent out to the legacy world. By default the
  // bridge only returns one when delivery FAILED, so this is usually a bounce.
  const [receipt, setReceipt] = useState<DeliveryReceiptView | null>(null);
  // Native-sender trust (§14): anchors the signature-verified header key to the
  // directory + the owner's allowlist. Independent of the body fetch.
  const [nativeTrust, setNativeTrust] = useState<SenderTrust | null>(null);
  // Pending-queue gate: a non-allowlisted sender's body stays hidden until the owner
  // either trusts them or explicitly reveals it as plain text (§14.2, accept-once).
  const [revealed, setRevealed] = useState(false);
  const [actioning, setActioning] = useState(false);

  const senderContact = contactByAddress(msg.senderAddress);
  // Content signature of the sender's allowlist entry — used as an effect dep so
  // trust re-evaluates only when the contact's provenance/pinned key actually
  // changes, not when a poll hands back a fresh (but equal) contacts array.
  const contactSig = senderContact ? `${senderContact.provenance ?? ''}:${senderContact.ed25519Pub ?? ''}` : '';

  // buildReply assembles the payload the composer needs: recipients (Reply vs Reply All),
  // the Gmail-style quoted original, and the threading metadata (continue the thread +
  // reference this message). Everything it reads is already in scope here.
  const me = address?.toLowerCase();
  const notMe = (a: string) => a.toLowerCase() !== me;
  const dedupe = (arr: string[]): string[] => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const a of arr) { const k = a.toLowerCase(); if (a && !seen.has(k)) { seen.add(k); out.push(a); } }
    return out;
  };
  const buildReply = (all: boolean): ComposeReplyTo => {
    // Reply to the sender; on my OWN message, reply to the original recipients instead.
    const primary = sentByMe ? dedupe([...msg.to, ...msg.cc].filter(notMe)) : dedupe([msg.senderAddress].filter(notMe));
    const to = primary.length ? primary : [msg.senderAddress];
    // Reply All adds every other original recipient (To+Cc) as Cc, minus me and the To set.
    // msg.bcc is ignored — it's only present on my own Sent copy, never on received mail.
    const cc = all
      ? dedupe([...msg.to, ...msg.cc]).filter(notMe).filter(a => !to.some(t => t.toLowerCase() === a.toLowerCase()))
      : [];
    // Gmail-style quoted original, in both renderings — the composer picks the one that
    // matches its mode. Omitted until the body has loaded, so an early Reply just opens
    // with an empty body.
    const who = senderContact?.name ? `${senderContact.name} <${msg.senderAddress}>` : msg.senderAddress;
    const when = `${formatDate(msg.sentAt)} at ${formatTime(msg.sentAt)}`;
    const quote = body != null
      ? `On ${when}, ${who} wrote:\n` + body.split('\n').map(l => (l ? `> ${l}` : '>')).join('\n')
      : undefined;
    // The HTML quote re-emits the ORIGINAL sender's markup, so it goes back through the
    // outgoing allowlist first — we must never sign and send another party's unfiltered
    // HTML. Inline images are dropped: their cid: references point at the original
    // message's attachments, which this new message doesn't carry.
    let quoteHtml: string | undefined;
    if (body != null) {
      const inner = htmlBody ? sanitizeOutgoing(htmlBody).html.replace(/<img\b[^>]*>/gi, '') : fromPlainText(body);
      quoteHtml =
        `<div>On ${escapeHtml(when)}, ${escapeHtml(who)} wrote:</div>` +
        `<blockquote>${inner}</blockquote>`;
    }
    return { to, cc, subject: msg.subject, quote, quoteHtml, replyToId: msg.messageId, threadId: msg.threadId };
  };
  // Show Reply All only when it would add recipients beyond the plain reply (a la Gmail).
  const replyAll = buildReply(true);
  const showReplyAll = (replyAll.cc?.length ?? 0) > 0;

  // Sent records from the personal store carry their own body (no mailbox fetch, no
  // bridge attestation). Otherwise fetch + verify the body on open (the inbox only
  // holds previews); for bridged legacy mail, verify the bridge's signed
  // classification attestation client-side before trusting the tier it claims.
  useEffect(() => {
    let cancelled = false;
    setBody(null);
    setBodyError(null);
    setHtmlBody(null);
    setAttachments([]);
    setAttestation(null);
    setReceipt(null);
    fetchFull(msg.hash)
      .then(full => {
        if (cancelled) return;
        setBody(full.bodyText);
        setHtmlBody(full.htmlBody ?? null);
        setAttachments(userAttachments(full.attachments));
        verifyBridgeAttestation(full.attachments)
          .then(a => { if (!cancelled) setAttestation(a); })
          .catch(() => { /* unexpected: treat as non-bridged, show no badge */ });
        // The receipt is signed by the BRIDGE, which is the sender of this message, so the
        // already-verified header key is what it must be bound to.
        const senderPub = msg.senderPublicKey ? fromHex(msg.senderPublicKey) : null;
        verifyDeliveryReceipt(full.attachments, senderPub)
          .then(r => { if (!cancelled) setReceipt(r); })
          .catch(() => { /* not a receipt, or unreadable: show no badge */ });
      })
      .catch(err => { if (!cancelled) setBodyError(err instanceof Error ? err.message : 'Failed to load message body'); });
    return () => { cancelled = true; };
  }, [msg.hash, fetchFull]);

  // Evaluate native-sender trust (skip your own Sent copies). The header key is
  // already signature-verified upstream; this anchors it to the directory + the
  // owner's allowlist. evaluateSenderTrust never throws. We do NOT blank the prior
  // verdict while re-resolving — keeping the last one visible avoids a badge flash on
  // a re-run; the msg.hash reset effect below clears it when a different message opens.
  useEffect(() => {
    if (ownMessage || !msg.senderPublicKey) { setNativeTrust(null); return; }
    let cancelled = false;
    evaluateSenderTrust(
      { senderAddress: msg.senderAddress, senderPublicKey: fromHex(msg.senderPublicKey), contact: senderContact },
      lookupIdentity,
    ).then(t => { if (!cancelled) setNativeTrust(t); }).catch(() => { if (!cancelled) setNativeTrust(null); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- senderContact tracked via contactSig
  }, [msg.hash, msg.senderAddress, msg.senderPublicKey, ownMessage, contactSig]);

  const av = attestation ? attestationView(attestation) : null;
  const rv = receipt ? receiptView(receipt) : null;
  // Native trust badge/callout — suppressed when a bridge attestation is shown
  // (bridged legacy mail: the DMCN "sender" is the bridge, not the real author), and
  // held back until the allowlist + filter are loaded so it resolves straight to the
  // correct verdict instead of flashing "unknown" first.
  const tv = contactsReady && filterReady && !av && !rv && nativeTrust ? senderTrustView(nativeTrust) : null;

  // Pending-queue category (§14.2). Your own Sent copies are never gated. Blocked/
  // pending senders' bodies stay behind the gate until trusted or revealed. trustReady
  // guards a cold load: don't gate (or show the body) until contacts + filter are
  // loaded, so we never flash the wrong state.
  const trustReady = ownMessage || (contactsReady && filterReady);
  const category = ownMessage ? 'allowlisted' : categorizeSender(msg.senderAddress, msg.senderPublicKey, senderContact, mailFilter);
  const gated = trustReady && category !== 'allowlisted';
  // Attachment downloads unlock on sender TRUST only (own message or allowlisted), or a
  // per-file "download anyway" acknowledgment. Deliberately independent of `revealed`.
  const downloadsUnlocked = ownMessage || category === 'allowlisted';
  // HTML renders ONLY for a trusted sender (mirrors downloadsUnlocked) — a pending
  // sender's plain-text peek shows escaped text, never rendered HTML.
  const htmlAllowed = !!htmlBody && downloadsUnlocked;
  // Inline images (disposition=inline) render inside the HTML body, so they're kept out
  // of the downloadable-attachment list.
  const downloadAttachments = attachments.filter(a => a.disposition !== 'inline');

  // Reset per-message UI (accept-once reveal + prior trust verdict) when the open
  // message changes, so nothing from the previous message lingers.
  useEffect(() => { setRevealed(false); setNativeTrust(null); setAckedDownloads(new Set()); setShowHtml(true); }, [msg.hash]);

  // Lazy key-pin (§14.1.2): once a message from an unpinned contact verifies with the
  // header key matching the directory key, record the facts so a later unsigned change
  // is detectable. Runs at most once per unpinned contact.
  //
  // `domain_verified` counts as well as `allowlisted`. Requiring allowlisting meant a
  // contact added by hand on the Contacts page — no provenance, no pinned key — never
  // gained key-change protection no matter how much mail passed between you. Both kinds
  // already establish that header key == directory key, which is the only precondition a
  // pin needs; allowlisting is a statement about trusting the person, not about whether
  // the key we just saw is the one the directory served.
  useEffect(() => {
    const pinnable = nativeTrust?.kind === 'allowlisted' || nativeTrust?.kind === 'domain_verified';
    if (ownMessage || !pinnable || !senderContact || senderContact.ed25519Pub) return;
    let cancelled = false;
    lookupIdentity(msg.senderAddress)
      .then(dir => { if (!cancelled) return pinKey(msg.senderAddress, directoryFacts(dir)); })
      .catch(() => { /* best effort */ });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- senderContact tracked via contactSig
  }, [msg.senderAddress, ownMessage, nativeTrust?.kind, contactSig, pinKey]);

  // §14.2.1 per-message actions.
  const handleTrust = async () => {
    setActioning(true);
    try {
      const dir = await lookupIdentity(msg.senderAddress);
      await allowlist({
        address: msg.senderAddress,
        name: senderContact?.name || msg.senderAddress,
        fingerprint: dir.fingerprint,
        provenance: 'user_approved',
        // Pin the DIRECTORY facts: if the key disagrees with the header key
        // (impersonation), the sender stays pending rather than being trusted into the
        // inbox. Trusting is a deliberate decision, so this REPLACES any pin this
        // device holds and advances the repin sequence (useContacts.allowlist) — it is
        // the "re-verify after a rotation" path.
        ...directoryFacts(dir),
      });
    } catch { /* leave pending; the badge already flags any problem */ }
    finally { setActioning(false); }
  };
  const handleBlock = async () => {
    setActioning(true);
    try {
      await blockSender(msg.senderAddress, msg.senderPublicKey);
      if (onDeleteOverride) await onDeleteOverride();
      else { await deleteMessage(msg.hash); await removeFlags(msg.hash); } // GC flag record
    } catch { /* ignore; close regardless */ }
    onBack();
  };

  const handleDelete = async () => {
    try {
      if (onDeleteOverride) await onDeleteOverride();
      else { await deleteMessage(msg.hash); await removeFlags(msg.hash); } // GC flag record
    } catch { /* ignore; close regardless */ }
    onBack();
  };

  // Full recipient audience from the signed header (fallback to the singular
  // recipientAddress for pre-feature messages). Bcc only appears on the sender's own
  // Sent copy — recipient copies never carry it.
  const toList = msg.to.length ? msg.to : msg.recipientAddress ? [msg.recipientAddress] : [];
  const counterparty = sentView ? toList[0] ?? '' : msg.senderAddress;
  // The name the owner gave this person, when they gave one. The ADDRESS stays the
  // identity everywhere it matters (routing, pinning, the title tip) — this is only
  // the label, and it must match what the mail list shows for the same person.
  const counterpartyName = nameFor(counterparty);
  const namedCounterparty = counterpartyName !== counterparty;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--surface-page)' }}>
      {/* Reader toolbar */}
      <div style={{ height: 52, flex: 'none', display: 'flex', alignItems: 'center', gap: 2, padding: '0 var(--space-3)', background: 'var(--surface-card)', borderBottom: '1px solid var(--border-default)' }}>
        <IconButton aria-label="Back to inbox" onClick={onBack}><Icon name="chevron-left" /></IconButton>
        <div style={{ flex: 1 }} />
        {onToggleStar && (
          <IconButton aria-label={starred ? 'Unstar' : 'Star'} onClick={onToggleStar}>
            <Icon name={starred ? 'star-fill' : 'star'} style={starred ? { color: 'var(--warning)' } : undefined} />
          </IconButton>
        )}
        {onArchive && (
          <IconButton aria-label={archived ? 'Unarchive' : 'Archive'} onClick={onArchive}><Icon name="archive" /></IconButton>
        )}
        <IconButton aria-label="Delete" onClick={handleDelete}><Icon name="trash" /></IconButton>
      </div>

      <div style={{ overflowY: 'auto', flex: 1, padding: mobile ? 'var(--space-4)' : 'var(--space-6) var(--space-8)' }}>
        <div style={{ maxWidth: 760, margin: '0 auto' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <h1 style={{ margin: 0, fontSize: mobile ? 'var(--text-xl)' : 'var(--text-2xl)', fontWeight: 600, letterSpacing: 'var(--tracking-tight)', color: 'var(--text-strong)' }}>
              {msg.subject || '(no subject)'}
            </h1>
            <Badge variant="brand" icon={<Icon name="lock" size={12} />}>Encrypted</Badge>
            {av && <Badge variant={av.variant} icon={<Icon name={av.icon} size={12} />}>{av.label}</Badge>}
            {rv && <Badge variant={rv.variant} icon={<Icon name={rv.icon} size={12} />}>{rv.label}</Badge>}
            {tv && <Badge variant={tv.variant} icon={<Icon name={tv.icon} size={12} />}>{tv.label}</Badge>}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginTop: 'var(--space-5)' }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div title={sentView ? toList.join(', ') : counterparty} style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {sentView
                  ? <>To <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>{toList.map(nameFor).join(', ')}</span></>
                  : <>{counterpartyName}{namedCounterparty && <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 'var(--space-2)' }}>{counterparty}</span>}</>}
              </div>
              {!sentView && toList.length > 0 && (
                <div title={toList.join(', ')} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  To {toList.map(nameFor).join(', ')}
                </div>
              )}
              {msg.cc.length > 0 && (
                <div title={msg.cc.join(', ')} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Cc {msg.cc.map(nameFor).join(', ')}
                </div>
              )}
              {msg.bcc.length > 0 && (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Bcc {msg.bcc.join(', ')}
                </div>
              )}
              <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
                {sentByMe ? 'from me' : 'to me'} &middot; {formatDate(msg.sentAt)} &middot; {formatTime(msg.sentAt)}
              </div>
            </div>
            <IconButton aria-label="Reply" onClick={() => onReply(buildReply(false))}><Icon name="reply" /></IconButton>
            {showReplyAll && (
              <IconButton aria-label="Reply all" onClick={() => onReply(replyAll)}><Icon name="reply-all" /></IconButton>
            )}
          </div>

          {(labels.length > 0 || folders.length > 0 || appliedLabels.length > 0 || currentFolder) && (
            <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)' }}>
              {appliedLabels.map(l => (
                <Tag key={l.id} color={l.color} onRemove={() => void removeLabel(msg.hash, l.id)}>{l.name}</Tag>
              ))}
              {availableLabels.length > 0 && (
                <select
                  value=""
                  aria-label="Add label"
                  onChange={e => { const id = e.target.value; e.currentTarget.value = ''; if (id) void addLabel(msg.hash, id); }}
                  style={assignSelectStyle}
                >
                  <option value="">+ Label</option>
                  {availableLabels.map(l => <option key={l.id} value={l.id}>{l.name}</option>)}
                </select>
              )}
              {folders.length > 0 && (
                <select
                  value={currentFolder ?? ''}
                  aria-label="Move to folder"
                  onChange={e => void setFolder(msg.hash, e.target.value || undefined)}
                  style={assignSelectStyle}
                >
                  <option value="">No folder</option>
                  {folders.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                </select>
              )}
            </div>
          )}

          {/* Pending-queue gate (§14.2): a non-allowlisted sender's body stays hidden
              behind a decision. "See as plain text" is a deliberate, small deviation
              from §14.2.1's strict hide — but DMCN bodies are text/plain rendered as an
              escaped React string (no HTML, images, or remote content), so revealing is
              inherently sanitized. Until trust data is loaded, show a neutral placeholder
              rather than flashing the gate or the body. */}
          {!trustReady ? (
            <div style={{ marginTop: 'var(--space-6)', minHeight: 80 }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>Loading…</span>
            </div>
          ) : gated && !revealed ? (
            <div style={{ marginTop: 'var(--space-6)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', background: 'var(--surface-sunken)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
                <Icon name="clock" size={18} style={{ color: 'var(--warning)', marginTop: 2, flex: 'none' }} />
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-strong)' }}>You don’t know this sender yet</div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 4 }}>
                    This message is genuine and end-to-end encrypted, but {counterparty} isn’t on your allowlist. Decide how to handle it before reading the contents.
                  </div>
                </div>
              </div>
              <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                <Button leftIcon={<Icon name="shield-check" size={16} />} onClick={handleTrust} disabled={actioning}>I trust the sender</Button>
                <Button variant="secondary" leftIcon={<Icon name="eye" size={16} />} onClick={() => setRevealed(true)}>See as plain text</Button>
                <Button variant="secondary" leftIcon={<Icon name="trash" size={16} />} onClick={handleDelete} disabled={actioning}>Delete this message</Button>
                <Button variant="danger" leftIcon={<Icon name="alert-octagon" size={16} />} onClick={handleBlock} disabled={actioning}>Block this sender</Button>
              </div>
            </div>
          ) : (
            <>
              {gated && revealed && (
                <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="eye" size={16} style={{ color: 'var(--warning)', flex: 'none' }} />
                  <span style={{ flex: 1, minWidth: 160 }}>Shown as plain text — you haven’t added this sender to your allowlist.</span>
                  <Button size="sm" leftIcon={<Icon name="shield-check" size={14} />} onClick={handleTrust} disabled={actioning}>Trust</Button>
                  <Button size="sm" variant="danger" leftIcon={<Icon name="alert-octagon" size={14} />} onClick={handleBlock} disabled={actioning}>Block</Button>
                </div>
              )}
              {htmlAllowed && (
                <div style={{ marginTop: 'var(--space-4)', display: 'flex', justifyContent: 'flex-end' }}>
                  <Button size="sm" variant="secondary" leftIcon={<Icon name={showHtml ? 'file' : 'mail'} size={14} />} onClick={() => setShowHtml(v => !v)}>
                    {showHtml ? 'View plain text' : 'View HTML'}
                  </Button>
                </div>
              )}
              {htmlAllowed && showHtml ? (
                <HtmlMessageBody html={htmlBody as string} attachments={attachments} />
              ) : (
                <div style={{ marginTop: 'var(--space-6)', fontSize: 'var(--text-base)', lineHeight: 'var(--leading-relaxed)', color: 'var(--text-body)', whiteSpace: 'pre-wrap', minHeight: 80 }}>
                  {bodyError && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                      <Icon name="alert-triangle" size={16} style={{ marginTop: 1 }} />
                      <span>Failed to load body: {bodyError}</span>
                    </div>
                  )}
                  {!bodyError && body === null && <span style={{ color: 'var(--text-muted)' }}>Loading…</span>}
                  {body !== null && body}
                </div>
              )}
            </>
          )}

          {/* Attachments: metadata is always shown; the download itself is disabled for a
              not-yet-trusted sender until they're trusted or the file is individually
              acknowledged. Files never open inline — always save-to-disk. */}
          {downloadAttachments.length > 0 && (
            <div style={{ marginTop: 'var(--space-6)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)' }}>
                <Icon name="paperclip" size={15} />
                {downloadAttachments.length} attachment{downloadAttachments.length > 1 ? 's' : ''}
              </div>
              {!downloadsUnlocked && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none' }} />
                  <span>Downloads are locked because you haven't trusted this sender. Files from unknown senders can be unsafe.</span>
                </div>
              )}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {downloadAttachments.map((a, i) => {
                  const enabled = downloadsUnlocked || ackedDownloads.has(i);
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-3)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', background: 'var(--surface-card)' }}>
                      <Icon name="file" size={18} style={{ color: 'var(--text-muted)', flex: 'none' }} />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-strong)', fontSize: 'var(--text-sm)' }}>{a.filename || 'attachment'}</div>
                        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{formatBytes(a.content.length)}{a.contentType ? ` \u00b7 ${a.contentType}` : ''}</div>
                      </div>
                      {enabled ? (
                        <Button size="sm" variant="secondary" leftIcon={<Icon name="download" size={14} />} onClick={() => downloadAttachment(a)}>Download</Button>
                      ) : (
                        <Button size="sm" variant="secondary" onClick={() => setAckedDownloads(s => new Set(s).add(i))}>Download anyway</Button>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div style={{ marginTop: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
            <Icon name="shield-check" size={16} />
            End-to-end encrypted over dmcn — only you and {counterpartyName} can read this.
          </div>

          {av && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${av.variant}-subtle)`, color: `var(--${av.variant === 'success' ? 'success' : av.variant === 'warning' ? 'warning' : 'danger'})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={av.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>{av.detail}</span>
            </div>
          )}

          {rv && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${rv.variant}-subtle)`, color: `var(--${rv.variant})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={rv.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>{rv.detail}</span>
            </div>
          )}

          {tv && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${tv.variant}-subtle)`, color: `var(--${tv.variant})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={tv.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>{tv.detail}</span>
            </div>
          )}

          <div style={{ marginTop: 'var(--space-6)', display: 'flex', gap: 'var(--space-2)' }}>
            <Button variant="secondary" leftIcon={<Icon name="reply" size={16} />} onClick={() => onReply(buildReply(false))}>Reply</Button>
            {showReplyAll && (
              <Button variant="secondary" leftIcon={<Icon name="reply-all" size={16} />} onClick={() => onReply(replyAll)}>Reply all</Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
