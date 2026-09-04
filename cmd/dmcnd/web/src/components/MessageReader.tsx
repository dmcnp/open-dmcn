import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { Preview, FullBody } from '../lib/api/mailboxRest';
import type { ComposeReplyTo } from '../lib/compose';
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
import type { DecryptedAttachment } from '../lib/crypto/split';
import { HtmlMessageBody } from './HtmlMessageBody';
import { sanitizeOutgoing } from '../lib/html/sanitize';
import { fromPlainText, escapeHtml } from '../lib/html/fromPlainText';
import { evaluateSenderTrust, type SenderTrust } from '../lib/crypto/senderTrust';
import { senderTrustView } from '../lib/trust/trustView';
import { useContacts } from '../lib/hooks/useContacts';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { useSettings } from '../lib/hooks/useSettings';
import { categorizeSender } from '../lib/trust/category';
import { directoryFacts } from '../lib/trust/pinnedKey';
import { senderLabel, sanitizeDisplayName } from '../lib/trust/displayName';
import { fromHex } from '../lib/crypto/keys';
import { deployment } from '@deployment';
import { formatBytes, formatDate, formatTime } from '../lib/format';

// attestationView maps a bridged-message verdict to its display treatment. Bridged mail is
// NEVER shown with a trust shield: even the best case (SPF/DKIM/DMARC pass + an operator-
// trusted bridge) is only domain-authentication relayed by a bridge you trust — not the
// end-to-end cryptographic identity a native dmcn sender carries. So the strongest tier is a
// NEUTRAL "Legacy email"; weaker outcomes are warning/danger. An unverified verdict is always
// danger, regardless of the (untrusted) tier it claims.
// authBreakdown renders the three checks behind the tier as one short line. Shown
// alongside the verdict because the tier alone cannot answer "which check did not
// pass" — and the answer changes what the reader should conclude. A message with
// spf=pass dmarc=pass dkim=none authenticated correctly under DMARC and simply missed
// this classifier's stricter DKIM-and-DMARC conjunction; one with dkim=fail did not.
//
// It also names the SMTP envelope sender when it differs from the displayed From address
// (bulk senders relay through a provider: From reddit.com, envelope …@amazonses.com). The
// displayed address is the identity DMARC checked; the envelope is who handed it over, and
// hiding that difference would be the kind of omission this client exists to avoid.
function authBreakdown(a: BridgeAttestation, senderAddress: string): string | null {
  const parts = [
    a.spf ? `SPF ${a.spf}` : null,
    a.dkim ? `DKIM ${a.dkim}` : null,
    a.dmarc ? `DMARC ${a.dmarc}` : null,
  ].filter(Boolean);
  const envelope = domainPart(a.smtpFrom);
  if (envelope && envelope !== domainPart(senderAddress)) parts.push(`via ${envelope}`);
  return parts.length ? parts.join(' · ') : null;
}

// domainPart returns the lower-cased domain of an address ('' when there isn't one).
function domainPart(addr: string): string {
  const at = (addr || '').lastIndexOf('@');
  return at >= 0 ? addr.slice(at + 1).toLowerCase() : '';
}

// senderAddress is the address the reader DISPLAYS (the message's From, which the bridge
// authenticated), not the classification's envelope sender — naming a bulk sender's
// per-message bounce address here told the reader a domain they never saw had been checked.
function attestationView(a: BridgeAttestation, senderAddress: string): {
  variant: 'neutral' | 'warning' | 'danger';
  icon: 'mail' | 'alert-triangle';
  label: string;
  detail: string;
} {
  if (!a.verified) {
    return {
      variant: 'danger',
      icon: 'alert-triangle',
      label: 'Unverified bridge',
      detail: `This message claims to arrive via an SMTP bridge that could not be verified${a.reason ? ` (${a.reason})` : ''}. Its sender cannot be confirmed — treat it with caution.`,
    };
  }
  const who = senderAddress || a.smtpFrom || 'the sender';
  const domain = domainPart(who);
  switch (a.trustTier) {
    case BridgeTrustTier.VerifiedLegacy:
      return {
        variant: 'neutral',
        icon: 'mail',
        label: 'Legacy email',
        detail: `Authenticated by ${domain ? `${domain}'s domain` : 'the sending domain'} (SPF/DKIM/DMARC) and relayed by a trusted bridge. Not end-to-end verified like a dmcn sender.`,
      };
    case BridgeTrustTier.Suspicious:
      return { variant: 'danger', icon: 'alert-triangle', label: 'Legacy email — failed checks', detail: `Legacy authentication (SPF/DKIM/DMARC) failed for ${who} — this sender may be forged. Treat it with caution.` };
    default:
      return { variant: 'warning', icon: 'alert-triangle', label: 'Legacy email — unauthenticated', detail: `${who}'s domain did not fully authenticate this message, so the sender can't be confirmed.` };
  }
}

// GateReason names WHY the pending-queue gate is holding a body back. The four reasons are
// not interchangeable, and the difference decides what the reader can DO about it: an unknown
// sender is a question about a PERSON, which trusting settles for good; a legacy message the
// bridge could not authenticate is a doubt about THIS message that no decision about the
// address can ever settle, because the address is precisely the part anyone can forge. Saying
// "you don't know this sender yet" in that second case both misdescribes the problem and
// points at an action that will not lift the gate.
type GateReason = 'blocked' | 'unauthenticated' | 'impersonation' | 'unknown';

// gateView is the gate's copy for one reason. `who` is the sender address as displayed,
// `bridged` whether the message arrived over legacy email (its unknown-sender case is a
// different statement: nothing about it is end-to-end verified), `known` whether the sender is
// already on the owner's allowlist.
function gateView(reason: GateReason, who: string, bridged: boolean, known: boolean): {
  icon: 'clock' | 'alert-triangle' | 'shield-off';
  color: string;
  title: string;
  detail: string;
} {
  switch (reason) {
    case 'blocked':
      return {
        icon: 'shield-off',
        color: 'var(--danger)',
        title: 'You blocked this sender',
        detail: `${who} is on your blocklist, so this message stays hidden. Manage the list in Settings if that was a mistake.`,
      };
    case 'unauthenticated':
      return {
        icon: 'alert-triangle',
        color: 'var(--warning)',
        title: `This message may not be from ${who}`,
        detail: known
          ? `You trust this sender, but legacy email carries no identity of its own and this message did not fully authenticate (details below) — so nothing here can confirm it really came from them. Trusting the address cannot answer that; this is a decision about this one message.`
          : `It came in over legacy email through a bridge and did not fully authenticate (details below), so anyone could have put ${who} on it. They are not on your allowlist either — decide how to handle it before reading the contents.`,
      };
    case 'impersonation':
      return {
        icon: 'alert-triangle',
        color: 'var(--danger)',
        title: 'Verify this sender before you read this',
        detail: `The key that signed this message is not the one the directory publishes for ${who} (details below). If they really did rotate their key, trusting them again re-checks it against the directory and clears this.`,
      };
    case 'unknown':
      // `known` is not redundant here: a sender ON the allowlist still reaches this gate when the
      // verdict that would have admitted them could not be reached (an unreachable directory, an
      // unverifiable bridge classification). Telling that reader they "don't know this sender"
      // and pointing them at an allowlist they already added them to describes neither.
      return {
        icon: 'clock',
        color: 'var(--warning)',
        title: known ? 'Check this message before you read it' : 'You don’t know this sender yet',
        detail: known
          ? `${bridged ? 'This message came in over legacy email through a bridge, so its sender isn’t cryptographically verified.' : 'This message is genuine and end-to-end encrypted.'} It still doesn’t match what you have on file for ${who} — confirm it before reading the contents.`
          : bridged
            ? `This message came in over legacy email through a bridge, so its sender isn’t cryptographically verified and it wasn’t end-to-end encrypted. ${who} isn’t on your allowlist — decide how to handle it before reading the contents.`
            : `This message is genuine and end-to-end encrypted, but ${who} isn’t on your allowlist. Decide how to handle it before reading the contents.`,
      };
  }
}

// calloutColors resolves the inline background/foreground for a trust callout. The neutral
// variant has no `--neutral-subtle` token, so map it explicitly to the sunken surface.
function calloutColors(variant: 'neutral' | 'success' | 'warning' | 'danger'): { bg: string; fg: string } {
  switch (variant) {
    case 'neutral': return { bg: 'var(--surface-sunken)', fg: 'var(--text-muted)' };
    case 'success': return { bg: 'var(--success-subtle)', fg: 'var(--success)' };
    case 'warning': return { bg: 'var(--warning-subtle)', fg: 'var(--warning)' };
    case 'danger': return { bg: 'var(--danger-subtle)', fg: 'var(--danger)' };
  }
}

// receiptView maps a delivery-receipt verdict to its display treatment: a verified receipt shows the
// bridge's delivered/failed outcome; an unverified one is a warning.
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

// Minimal themed style for the native label/folder assignment selects.
const assignSelectStyle: CSSProperties = {
  font: 'inherit', fontSize: 'var(--text-sm)', color: 'var(--text-body)',
  background: 'var(--surface-card)', border: '1px solid var(--border-default)',
  borderRadius: 'var(--radius-sm)', padding: '3px 8px', cursor: 'pointer',
};


// System attachments carried for protocol purposes are consumed elsewhere and hidden
// from the user-facing attachment list: the bridge attestation and delivery receipt, the
// raw legacy source, and whatever control payloads this deployment carries.
// Built on demand, not at module load: `deployment` imports the screens it contributes, so
// reading it while THIS module is being evaluated would depend on which side of that cycle
// loaded first. A function has no such ordering to get wrong.
function internalAttachmentTypes(): Set<string> {
  return new Set<string>([
    CLASSIFICATION_CONTENT_TYPE,
    RECEIPT_CONTENT_TYPE,
    'message/rfc822', // original.eml — raw legacy email preserved by the bridge
    ...deployment.internalAttachmentTypes,
  ]);
}
function userAttachments(all: DecryptedAttachment[]): DecryptedAttachment[] {
  const internal = internalAttachmentTypes();
  return all.filter(a => !internal.has(a.contentType));
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

// downloadAttachment saves an attachment via a transient blob: URL. The blob is
// revoked on a delay so the (up to 25 MB) bytes aren't retained; nothing is opened
// inline, so a hostile content type can't execute in-page.
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
  const { settings } = useSettings();

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

  const [body, setBody] = useState<string | null>(null);
  const [bodyError, setBodyError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<BridgeAttestation | null>(null);
  // Delivery receipt: a bridge's signed confirmation that an outbound-to-legacy message we sent was
  // delivered (or failed). Verified server-side against the operator key, like a classification.
  const [receipt, setReceipt] = useState<DeliveryReceiptView | null>(null);
  // Whether the bridge attestation/receipt has settled (a verdict OR confirmed-none). The
  // sender_address of a bridged message is a legacy email, indistinguishable from a native one
  // until the classification verifies — so gate the trust UI on this to avoid flashing the wrong
  // verdict (or acting on the shared bridge key) before we know it's bridged.
  const [bridgeResolved, setBridgeResolved] = useState(false);
  // Native-sender trust (§14): anchors the signature-verified header key to the
  // directory + the owner's allowlist. Independent of the body fetch.
  const [nativeTrust, setNativeTrust] = useState<SenderTrust | null>(null);
  // Whether the directory verdict has SETTLED for this message. Distinct from
  // `nativeTrust !== null`, which can't tell "still resolving" from "resolved to nothing" —
  // and the gate must fail closed on the former. Reset per message by the msg.hash effect.
  const [nativeTrustReady, setNativeTrustReady] = useState(false);
  // Pending-queue gate: a non-allowlisted sender's body stays hidden until the owner
  // either trusts them or explicitly reveals it as plain text (§14.2, accept-once).
  const [revealed, setRevealed] = useState(false);
  // The owner's explicit decision about THIS message — the escape hatch for the gates that
  // trusting an address cannot lift. Bridged legacy mail whose SPF/DKIM/DMARC checks did not
  // pass is re-gated on every arrival by design (the address alone is spoofable, so an
  // allowlist entry can't stand in for the authentication that is missing); without a
  // per-message override there would be no way to ever read one. Deliberately scoped to the
  // open message: it unlocks exactly what trusting the sender unlocks (the HTML rendering,
  // attachment downloads) and asserts nothing about the next message claiming the same address.
  const [messageTrusted, setMessageTrusted] = useState(false);
  const [actioning, setActioning] = useState(false);
  // User-facing attachments (internal/protocol ones filtered out) + per-file download
  // acknowledgments. Downloads are gated on sender TRUST, NOT on `revealed`: the
  // plain-text peek is safe because text is escaped; a binary download is not.
  const [attachments, setAttachments] = useState<DecryptedAttachment[]>([]);
  const [ackedDownloads, setAckedDownloads] = useState<Set<number>>(new Set());
  // The text/html rendering (when the message carries one). Rendered sanitized in a
  // sandboxed iframe — but ONLY for a trusted sender; a pending sender's plain-text
  // peek never renders HTML. `showHtml` toggles the HTML vs plain-text view.
  const [htmlBody, setHtmlBody] = useState<string | null>(null);
  const [showHtml, setShowHtml] = useState(true);

  const senderContact = contactByAddress(msg.senderAddress);
  // Content signature of the sender's allowlist entry — used as an effect dep so
  // trust re-evaluates only when the contact's provenance/pinned key actually
  // changes, not when a poll hands back a fresh (but equal) contacts array.
  const contactSig = senderContact
    ? [
        senderContact.provenance ?? '', senderContact.ed25519Pub ?? '', senderContact.x25519Pub ?? '',
        senderContact.bridgeCapability ? '1' : '', senderContact.adminKeyCustody ? '1' : '', senderContact.pinSeq ?? 0,
      ].join(':')
    : '';

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
  // Show Reply All only when it would add recipients beyond the plain reply (à la Gmail).
  const replyAll = buildReply(true);
  const showReplyAll = (replyAll.cc?.length ?? 0) > 0;

  // Fetch + verify the body on open (the inbox list only holds previews). Sent messages
  // use openFull to read their self-sealed envelope from the personal store; either way
  // it's the same FullBody. For bridged legacy mail, verify the bridge's signed
  // classification attestation client-side before trusting the tier it claims.
  useEffect(() => {
    let cancelled = false;
    setBody(null);
    setBodyError(null);
    setAttestation(null);
    setReceipt(null);
    setAttachments([]);
    setHtmlBody(null);
    setBridgeResolved(false);
    (openFull ?? openMessageFull)(msg.hash)
      .then(async full => {
        if (cancelled) return;
        setBody(full.bodyText);
        setHtmlBody(full.htmlBody ?? null);
        setAttachments(userAttachments(full.attachments));
        const senderPub = msg.senderPublicKey ? fromHex(msg.senderPublicKey) : null;
        // Resolve both attestations before revealing the trust UI (each fails closed to null).
        const [a, r] = await Promise.all([
          verifyBridgeAttestation(full.attachments, senderPub).catch(() => null),
          verifyDeliveryReceipt(full.attachments, senderPub).catch(() => null),
        ]);
        if (cancelled) return;
        setAttestation(a);
        setReceipt(r);
        setBridgeResolved(true);
      })
      .catch(err => {
        if (cancelled) return;
        setBodyError(err instanceof Error ? err.message : 'Failed to load message body');
        setBridgeResolved(true); // body failed — unblock the UI so the error can render.
      });
    return () => { cancelled = true; };
  }, [msg.hash, msg.senderPublicKey, openMessageFull, openFull]);

  // Evaluate native-sender trust (skip your own Sent copies). The header key is
  // already signature-verified upstream; this anchors it to the directory + the
  // owner's allowlist. evaluateSenderTrust never throws. We do NOT blank the prior
  // verdict while re-resolving — keeping the last one visible avoids a badge flash on
  // a re-run; the msg.hash reset effect below clears it when a different message opens.
  useEffect(() => {
    // No native anchor is obtainable here (own mail, or no header key at all), so mark it
    // settled — otherwise the gate would fail closed forever on a message it can't anchor.
    if (ownMessage || !msg.senderPublicKey) { setNativeTrust(null); setNativeTrustReady(true); return; }
    let cancelled = false;
    evaluateSenderTrust(
      { senderAddress: msg.senderAddress, senderPublicKey: fromHex(msg.senderPublicKey), contact: senderContact },
      lookupIdentity,
    )
      .then(t => { if (!cancelled) setNativeTrust(t); })
      .catch(() => { if (!cancelled) setNativeTrust(null); })
      .finally(() => { if (!cancelled) setNativeTrustReady(true); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- senderContact tracked via contactSig
  }, [msg.hash, msg.senderAddress, msg.senderPublicKey, ownMessage, contactSig]);

  const av = attestation ? attestationView(attestation, msg.senderAddress) : null;
  const rv = receipt ? receiptView(receipt) : null;
  // Native trust badge/callout — suppressed when a bridge attestation is shown (bridged legacy
  // mail: sender_address is a legacy email vouched for by the bridge, not a native identity), and
  // held back until contacts + filter + the bridge attestation have all settled so it resolves
  // straight to the correct verdict instead of flashing "unknown" (or a native verdict on a
  // legacy address) first.
  const tv = contactsReady && filterReady && bridgeResolved && !av && !rv && nativeTrust ? senderTrustView(nativeTrust) : null;
  // A verified bridge classification means the DMCN "sender" is a legacy email relayed by a
  // trusted bridge. Allowlist/block it by ADDRESS only — there is no directory key to pin, and the
  // shared bridge key (in sender_public_key) must never be pinned or blocked.
  const bridgedLegacy = attestation?.verified === true;

  // `attestation.verified` only proves the BRIDGE credential chains to an operator-trusted key —
  // it says NOTHING about whether the legacy sender passed SPF/DKIM/DMARC (that verdict is the
  // signed trust tier). Only a VerifiedLegacy tier is an actual anti-spoof proof: the bridge
  // rejects at SMTP solely on DMARC-fail-under-p=reject, so a spoof of a domain publishing no
  // SPF/DKIM arrives as UnverifiedLegacy and would otherwise sail through on the address alone.
  const bridgeAuthenticated = bridgedLegacy && attestation?.trustTier === BridgeTrustTier.VerifiedLegacy;
  // The directory's active-distrust verdicts. evaluateSenderTrust already computes these; before
  // this they only drove the badge, so a message whose displayed sender the directory disowns
  // could still open if that address happened to sit in the address book.
  const nativeDanger = !bridgedLegacy && nativeTrust !== null
    && (nativeTrust.kind === 'key_mismatch' || nativeTrust.kind === 'key_changed' || nativeTrust.kind === 'identity_unverifiable');

  // Pending-queue category (§14.2). Your own Sent copies are never gated. Blocked/
  // pending senders' bodies stay behind the gate until trusted or revealed.
  //
  // A VERIFIED delivery receipt is the bridge's signed confirmation of your own outbound mail
  // (not an unknown sender) — bypass the pending gate. Only when verified: a spoofer can't forge
  // an operator-trusted bridge's receipt, so this can't be used to smuggle content past the gate.
  const trustBypass = ownMessage || receipt?.verified === true;
  const base: 'allowlisted' | 'pending' | 'blocked' = trustBypass
    ? 'allowlisted'
    : categorizeSender(msg.senderAddress, msg.senderPublicKey, senderContact, mailFilter);
  // A keyless (address-only) allowlist entry is a legacy sender: it has no pinned key because the
  // legacy sender has no DMCN keypair. The address alone is spoofable (any DMCN peer can put it in
  // a header), so it is NOT self-authenticating — the real anti-spoof proof is the bridge's signed
  // SPF/DKIM/DMARC classification. So honor a legacy allowlist entry ONLY for a bridge-AUTHENTICATED
  // message; a claimed-but-unauthenticated legacy address stays gated (possible spoof).
  const senderIsLegacyContact = !!senderContact && !senderContact.ed25519Pub && !!senderContact.provenance;

  // trustReady guards a cold load: don't gate (or show the body) until contacts + filter are
  // loaded, so we never flash the wrong state. A native sender the contact list would admit also
  // needs its directory anchor to have SETTLED — an address-book entry is not itself proof of
  // identity, so opening before the verdict lands would render content we might then retract.
  const needsNativeAnchor = !trustBypass && !bridgedLegacy && base === 'allowlisted';
  const trustReady = ownMessage
    || (contactsReady && filterReady && bridgeResolved && (!needsNativeAnchor || nativeTrustReady));

  let category: 'allowlisted' | 'pending' | 'blocked';
  if (trustBypass || base !== 'allowlisted') {
    category = base;
  } else if (senderIsLegacyContact && !bridgeAuthenticated) {
    category = 'pending'; // legacy address vouched for by nothing the bridge actually verified
  } else if (nativeDanger) {
    category = 'pending'; // the directory disowns the key that signed this header
  } else {
    category = base;
  }
  // The reason the gate will give, derived from the same facts that closed it.
  const gateReason: GateReason = category === 'blocked'
    ? 'blocked'
    : bridgedLegacy && !bridgeAuthenticated
      ? 'unauthenticated'
      : nativeDanger
        ? 'impersonation'
        : 'unknown';
  // "I trust the sender" is offered only where it can actually change the outcome. For an
  // allowlisted legacy sender whose message failed its checks it provably cannot — the entry
  // is already there and the bridge still cannot authenticate this message — and for a blocked
  // sender the filter decides before the allowlist is ever consulted. A button that silently
  // does nothing is what made trusting feel broken on exactly the mail that needs the decision.
  const trustActionable = gateReason !== 'blocked' && !(senderIsLegacyContact && gateReason === 'unauthenticated');
  // The per-message override, offered exactly where trusting the address cannot lift the gate.
  // Not for 'blocked' (that gate is the owner's own standing decision, lifted by unblocking)
  // and not for 'impersonation' (the directory says this signature is not the sender's, so the
  // safe plain-text peek stays the only way in — re-verifying the key is the real remedy).
  const overrideActionable = gateReason === 'unauthenticated';
  const gated = trustReady && category !== 'allowlisted' && !messageTrusted;
  // Attachment downloads unlock on sender TRUST (own message or allowlisted) or on the owner's
  // explicit decision about this message, plus the per-file "download anyway" acknowledgment.
  // Deliberately independent of `revealed`: the plain-text peek is safe because the text is
  // escaped and a binary download is not, so peeking is not a decision.
  const downloadsUnlocked = ownMessage || category === 'allowlisted' || messageTrusted;
  // HTML renders ONLY for a trusted sender (mirrors downloadsUnlocked) — a pending
  // sender's "See as plain text" peek shows escaped text, never rendered HTML.
  const htmlAllowed = !!htmlBody && downloadsUnlocked;
  // Remote images ride on htmlAllowed rather than on a gate of their own, so opting in can
  // only change WHAT a trusted sender's HTML may fetch — never WHICH senders get HTML. Off
  // by default; the reader turns it on in Settings → Privacy & security.
  const remoteImagesAllowed = htmlAllowed && settings.remoteImagesForTrusted === true;
  // Inline images (disposition=inline) render inside the HTML body, so they're kept out
  // of the downloadable-attachment list.
  const downloadAttachments = attachments.filter(a => a.disposition !== 'inline');

  // Reset per-message UI (accept-once reveal + prior trust verdict) when the open
  // message changes, so nothing from the previous message lingers.
  useEffect(() => { setRevealed(false); setMessageTrusted(false); setNativeTrust(null); setNativeTrustReady(false); setAckedDownloads(new Set()); setShowHtml(true); }, [msg.hash]);

  // Lazy key-pin (§14.1.2): once a message from an unpinned CONTACT verifies with the header key
  // matching the directory key, record the keys so a later unsigned change is detectable. Runs at
  // most once per unpinned contact.
  //
  // Deliberately covers 'domain_verified' as well as 'allowlisted'. Pinning used to require the
  // contact to be allowlisted, which meant a contact added by hand on the Contacts page — no
  // provenance, no pinned key — never gained key-change protection no matter how much mail passed
  // between you. Both kinds already establish that header key == directory key, which is the only
  // precondition a pin needs; allowlisting is a statement about trusting the person, not about
  // whether the key we just saw is the one the directory served.
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
      if (bridgedLegacy) {
        // Legacy sender relayed by a trusted bridge: no DMCN directory entry / key to pin —
        // keyless allowlist by address (a user-discretion "I trust this email", not a key anchor).
        //
        // The name defaults to the one the message carried, because the owner clicked trust on a
        // screen showing that name AND the address together — so adopting it is what they meant.
        // From here it is an OWNER-given contact name like any other, which is why it is taken at
        // this deliberate moment and never silently.
        await allowlist({
          address: msg.senderAddress,
          name: senderContact?.name || sanitizeDisplayName(msg.senderDisplay) || msg.senderAddress,
          fingerprint: '',
          provenance: 'user_approved',
        });
        // The owner made this decision with this message's verdict in front of them, so it
        // opens THIS message — even though the allowlist entry alone will not open the next
        // one (unauthenticated legacy mail is re-gated every time, above). Without this the
        // click was a silent no-op on precisely the mail it was offered for: the contact was
        // written, the gate stayed shut, and nothing said why.
        setMessageTrusted(true);
      } else {
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
      }
    } catch { /* leave pending; the badge already flags any problem */ }
    finally { setActioning(false); }
  };
  const handleBlock = async () => {
    setActioning(true);
    try {
      // For bridged legacy mail, block by ADDRESS only: msg.senderPublicKey is the shared bridge
      // key, so key-blocking it would block ALL bridged mail. (Relay-side key blocking can't apply
      // to a legacy sender anyway — the relay only ever sees the bridge; this hides it locally.)
      await blockSender(msg.senderAddress, bridgedLegacy ? undefined : msg.senderPublicKey);
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
  // The header labels people by the name the owner gave them in Contacts first, then by
  // the display name the message itself carried (legacy mail's From name), then by the
  // address. The address stays visible alongside either name, so the actual identity is
  // never hidden behind a nickname — or behind a name a sender chose for itself.
  const contactName = nameFor(counterparty);
  const { primary: counterpartyName, secondary: counterpartyAddress } =
    senderLabel(counterparty, contactName, sentView ? '' : msg.senderDisplay);
  const namedCounterparty = counterpartyAddress !== '';
  // The gate's copy, resolved once from the reason the gate closed for.
  const gv = gateView(gateReason, counterparty, !!av, !!senderContact);

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
            {/* Legacy mail is encrypted only on the bridge→you hop (it crossed plaintext SMTP
                first), so tone the badge down from the brand "Encrypted" (which signals full E2E)
                to a neutral "Encrypted to you". The callout below spells out the caveat. */}
            <Badge variant={av ? 'neutral' : 'brand'} icon={<Icon name="lock" size={12} />}>{av ? 'Encrypted to you' : 'Encrypted'}</Badge>
            {av && <Badge variant={av.variant} icon={<Icon name={av.icon} size={12} />}>{av.label}</Badge>}
            {rv && <Badge variant={rv.variant} icon={<Icon name={rv.icon} size={12} />}>{rv.label}</Badge>}
            {tv && <Badge variant={tv.variant} icon={<Icon name={tv.icon} size={12} />}>{tv.label}</Badge>}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginTop: 'var(--space-5)' }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div title={sentView ? toList.join(', ') : counterparty} style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {sentView
                  ? <>To <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>{toList.map(nameFor).join(', ')}</span></>
                  : <>{counterpartyName}{namedCounterparty && <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 'var(--space-2)' }}>{counterpartyAddress}</span>}</>}
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
                <div title={msg.bcc.join(', ')} style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Bcc {msg.bcc.map(nameFor).join(', ')}
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
              inherently sanitized. "Show this message" is the fuller override, offered
              only where the gate is about THIS message rather than about the sender: it
              grants the open message what trusting the sender would grant it, and expires
              with it. Until trust data is loaded, show a neutral placeholder rather than
              flashing the gate or the body. */}
          {!trustReady ? (
            <div style={{ marginTop: 'var(--space-6)', minHeight: 80 }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-base)' }}>Loading…</span>
            </div>
          ) : gated && !revealed ? (
            <div style={{ marginTop: 'var(--space-6)', padding: 'var(--space-4)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', background: 'var(--surface-sunken)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
                <Icon name={gv.icon} size={18} style={{ color: gv.color, marginTop: 2, flex: 'none' }} />
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--text-strong)' }}>{gv.title}</div>
                  <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 4 }}>{gv.detail}</div>
                </div>
              </div>
              <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                {trustActionable && (
                  <Button leftIcon={<Icon name="shield-check" size={16} />} onClick={handleTrust} disabled={actioning}>I trust the sender</Button>
                )}
                {overrideActionable && (
                  <Button variant={trustActionable ? 'secondary' : 'primary'} leftIcon={<Icon name="unlock" size={16} />} onClick={() => setMessageTrusted(true)}>Show this message</Button>
                )}
                <Button variant="secondary" leftIcon={<Icon name="eye" size={16} />} onClick={() => setRevealed(true)}>See as plain text</Button>
                <Button variant="secondary" leftIcon={<Icon name="trash" size={16} />} onClick={handleDelete} disabled={actioning}>Delete this message</Button>
                {gateReason !== 'blocked' && (
                  <Button variant="danger" leftIcon={<Icon name="alert-octagon" size={16} />} onClick={handleBlock} disabled={actioning}>Block this sender</Button>
                )}
              </div>
            </div>
          ) : (
            <>
              {messageTrusted && category !== 'allowlisted' && (
                <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="unlock" size={16} style={{ color: 'var(--warning)', flex: 'none' }} />
                  <span style={{ flex: 1, minWidth: 160 }}>Shown because you asked for it. Nothing about the sender changed — the checks below still stand, and the next message from this address will ask again.</span>
                  <Button size="sm" variant="danger" leftIcon={<Icon name="alert-octagon" size={14} />} onClick={handleBlock} disabled={actioning}>Block</Button>
                </div>
              )}
              {gated && revealed && (
                <div style={{ marginTop: 'var(--space-4)', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="eye" size={16} style={{ color: 'var(--warning)', flex: 'none' }} />
                  <span style={{ flex: 1, minWidth: 160 }}>
                    {overrideActionable
                      ? `Shown as plain text — nothing could authenticate this message’s sender.${htmlBody ? ' The HTML version stays hidden until you choose to show it.' : ''}`
                      : `Shown as plain text — you haven’t added this sender to your allowlist.${htmlBody ? ' The HTML version stays hidden until you trust the sender.' : ''}`}
                  </span>
                  {trustActionable && (
                    <Button size="sm" leftIcon={<Icon name="shield-check" size={14} />} onClick={handleTrust} disabled={actioning}>Trust</Button>
                  )}
                  {overrideActionable && (
                    <Button size="sm" variant={trustActionable ? 'secondary' : 'primary'} leftIcon={<Icon name="unlock" size={14} />} onClick={() => setMessageTrusted(true)}>Show this message</Button>
                  )}
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
                <HtmlMessageBody html={htmlBody as string} attachments={attachments} allowRemoteImages={remoteImagesAllowed} />
              ) : (
                <div style={{ marginTop: 'var(--space-6)', fontSize: 'var(--text-base)', lineHeight: 'var(--leading-relaxed)', color: 'var(--text-body)', whiteSpace: 'pre-wrap', minHeight: 80 }}>
                  {bodyError && (
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                      <Icon name="alert-triangle" size={16} style={{ marginTop: 1 }} />
                      <span>Failed to load body: {bodyError}</span>
                    </div>
                  )}
                  {!bodyError && body === null && <span style={{ color: 'var(--text-muted)' }}>Loading…</span>}
                  {/* An empty text rendering is a real outcome, not a failure — an image-only
                      campaign mail renders down to no text at all — but an empty panel reads as
                      one. Say which it is, and say it especially behind the gate, where the
                      reader's next move is a decision about HTML they have not been shown. */}
                  {body !== null && body.trim() === '' && (
                    <span style={{ color: 'var(--text-muted)' }}>
                      {htmlBody
                        ? 'This message has no text version — everything it says is in its HTML rendering.'
                        : 'This message has no text content.'}
                    </span>
                  )}
                  {body !== null && body.trim() !== '' && body}
                </div>
              )}
            </>
          )}

          {/* Attachments (§ trust gate): metadata is always shown; the actual download
              is disabled for a not-yet-trusted sender until they're trusted or the file
              is individually acknowledged. Files never open inline — always save-to-disk. */}
          {downloadAttachments.length > 0 && (
            <div style={{ marginTop: 'var(--space-6)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)' }}>
                <Icon name="paperclip" size={15} />
                {downloadAttachments.length} attachment{downloadAttachments.length > 1 ? 's' : ''}
              </div>
              {!downloadsUnlocked && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--warning-subtle)', color: 'var(--text-body)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
                  <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none' }} />
                  <span>Downloads are locked because you haven’t trusted this sender. Files from unknown senders can be unsafe.</span>
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
                        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>{formatBytes(a.content.length)}{a.contentType ? ` · ${a.contentType}` : ''}</div>
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

          {av ? (
            <div style={{ marginTop: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--surface-sunken)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name="mail" size={16} />
              Encrypted from the bridge to you. The original email crossed standard email (SMTP) before reaching the bridge, which isn’t end-to-end encrypted.
            </div>
          ) : rv ? null : (
            <div style={{ marginTop: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name="shield-check" size={16} />
              End-to-end encrypted over dmcn — only you and {contactName} can read this.
            </div>
          )}

          {av && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: calloutColors(av.variant).bg, color: calloutColors(av.variant).fg, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={av.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>
                {av.detail}
                {attestation && authBreakdown(attestation, msg.senderAddress) && (
                  <span style={{ display: 'block', marginTop: 'var(--space-1)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', opacity: 0.85 }}>
                    {authBreakdown(attestation, msg.senderAddress)}
                  </span>
                )}
              </span>
            </div>
          )}

          {rv && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${rv.variant}-subtle)`, color: `var(--${rv.variant === 'success' ? 'success' : rv.variant === 'warning' ? 'warning' : 'danger'})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
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
