import type { ComposeReplyTo } from '../lib/compose';
import { deployment } from '@deployment';
import { useState, useRef, useEffect } from 'react';
import type { CSSProperties, ReactNode, KeyboardEvent } from 'react';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { lookupIdentity, sendMessage, ApiError } from '../lib/api/client';
import { absentIdentityFacts, checkPin, changedFacts, contactFacts, directoryFacts, pinnedIdentityGoneWarning, pinnedKeyWarning, type PinnedFacts } from '../lib/trust/pinnedKey';
import { encryptSplit, type SplitEnvelope, type AttachmentInput } from '../lib/crypto/split';
import { encodeSplitEnvelope } from '../lib/crypto/protobuf';
import { signWithKey } from '../lib/crypto/sign';
import { toBase64, fromBase64, toHex, fromHex } from '../lib/crypto/keys';
import { SentStore } from '../lib/api/sentStore';
import { useSettings } from '../lib/hooks/useSettings';
import { useContacts, type Contact } from '../lib/hooks/useContacts';
import { DEFAULT_DOMAIN } from '../lib/config';
import { Button, IconButton, Tag } from '../ds';
import { Icon } from './Icon';
import { RichTextEditor, type RichTextEditorHandle, type InsertedImage } from './RichTextEditor';
import { sanitizeOutgoing } from '../lib/html/sanitize';
import { toPlainText } from '../lib/html/toPlainText';
import { fromPlainText } from '../lib/html/fromPlainText';
import { bufferSource } from '../lib/crypto/bytes';


// Total attachment cap per message (body + all attachments ride inline in one sealed
// blob). ~25 MB: works with the existing size-class padding (rounds to whole MB above
// 1 MB) and stays reasonable for browser memory + the relay's in-memory store.
const MAX_TOTAL_ATTACHMENT_BYTES = 25 * 1024 * 1024;

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

// truncateFilename shortens a long name in the MIDDLE so the chip fits the compose
// box while keeping the start and the extension (the full name is in the title tip).
function truncateFilename(name: string, max = 28): string {
  if (name.length <= max) return name;
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 && name.length - dot <= 6 ? name.slice(dot) : '';
  const keep = Math.max(6, max - ext.length - 1);
  return name.slice(0, keep) + '…' + ext;
}

// newUuid returns 16 random bytes with RFC-4122 v4 bits set (attachment_id / message id).
function newUuid(): Uint8Array {
  const id = crypto.getRandomValues(new Uint8Array(16));
  id[6] = (id[6] & 0x0f) | 0x40;
  id[8] = (id[8] & 0x3f) | 0x80;
  return id;
}

// How a recipient can receive this message, driving the chip's shield:
//  - trusted: in the owner's contact list (allowlisted)     → blue shield
//  - dmcn:    a DMCN identity, not (yet) a contact           → green shield
//  - legacy:  no DMCN identity (legacy email via a bridge)   → amber warning, NOT E2E
type RecipientKind = 'trusted' | 'dmcn' | 'legacy';

function recipientChip(kind: RecipientKind | undefined): {
  icon: 'shield-check' | 'shield' | 'alert-triangle';
  color: string;
  title: string;
} {
  switch (kind) {
    case 'trusted': return { icon: 'shield-check', color: 'var(--trust-contact)', title: 'Trusted contact' };
    case 'dmcn':    return { icon: 'shield-check', color: 'var(--trust-dmcn)', title: 'DMCN recipient — end-to-end encrypted' };
    case 'legacy':  return { icon: 'alert-triangle', color: 'var(--warning)', title: 'Legacy email — cannot be end-to-end encrypted' };
    default:        return { icon: 'shield', color: 'var(--text-muted)', title: 'Checking recipient…' };
  }
}

export interface ComposeDialogProps {
  onClose: () => void;
  /** When set, pre-fills the recipient and a "Re:" subject. */
  replyTo?: ComposeReplyTo | null;
  /** Called after a successful send so the inbox can refresh. */
  onSent?: () => void;
  /** Full-screen sheet on mobile instead of the floating desktop window. */
  mobile?: boolean;
}

/**
 * Floating in-page compose window (the design's Compose pattern). Rendered inside
 * the inbox main column rather than as a standalone route. All crypto happens here
 * in the browser; the private key never leaves it.
 */
export function ComposeDialog({ onClose, replyTo = null, onSent, mobile = false }: ComposeDialogProps) {
  const { address } = useAuth();
  const { keys } = useKeys();
  const { settings } = useSettings();
  const { contacts, nameFor, contactByAddress, pinKey, allowlist } = useContacts();

  // Three recipient classes with standard email semantics. To/Cc are visible to
  // everyone; Bcc is only recorded on the sender's own Sent copy (see handleSend).
  const [to, setTo] = useState<string[]>(replyTo?.to ?? []);
  const [cc, setCc] = useState<string[]>(replyTo?.cc ?? []);
  const [bcc, setBcc] = useState<string[]>([]);
  const [pendingTo, setPendingTo] = useState('');
  const [pendingCc, setPendingCc] = useState('');
  const [pendingBcc, setPendingBcc] = useState('');
  // Reveal Cc/Bcc up front when a Reply All prefilled Cc recipients.
  const [showCcBcc, setShowCcBcc] = useState(!!replyTo?.cc?.length);
  const [subject, setSubject] = useState(replyTo?.subject ? `Re: ${replyTo.subject.replace(/^Re:\s*/i, '')}` : '');

  // A reply prefills the composer with the quoted original, signature ABOVE the quote
  // (top-posted). Both renderings are built the same way so switching modes keeps the
  // same shape; the leading blank line is where the user types.
  const plainScaffold = (sig: string): string => {
    if (!replyTo && !sig) return '';
    const quote = replyTo?.quote ?? '';
    return '\n\n' + (sig ? sig + (quote ? '\n\n' + quote : '') : quote);
  };
  const htmlScaffold = (sig: string): string => {
    const quote = replyTo?.quoteHtml ?? '';
    if (!replyTo && !sig) return '';
    const out = ['<div><br></div>'];
    if (sig) out.push(fromPlainText(sig));
    if (quote) out.push('<div><br></div>', quote);
    return out.join('');
  };

  // Rich (HTML) is the system default for every compose; the account setting may flip the
  // STARTING mode, and the footer toggle overrides it for this message only.
  const [richMode, setRichMode] = useState(() => settings.composePlainText !== true);
  const [body, setBody] = useState(() => plainScaffold(settings.signature ?? ''));
  const editorRef = useRef<RichTextEditorHandle>(null);
  // The editor is uncontrolled and reads this only when it mounts, so it doubles as the
  // seed for a plain → rich switch (which is exactly when it mounts).
  const richInitial = useRef(htmlScaffold(settings.signature ?? ''));
  // Set once the user edits either body, so a late-loading settings doc never clobbers it.
  const dirtyRef = useRef(false);

  // Attachments ride inline in the sealed body blob (one CEK). Read fully into memory
  // here; the crypto layer already round-trips AttachmentInput end-to-end. The ref is
  // authoritative because images are inserted from async handlers that would otherwise
  // read a stale `attachments` closure mid-batch.
  const [attachments, setAttachments] = useState<AttachmentInput[]>([]);
  const attachmentsRef = useRef<AttachmentInput[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Onion routing is no longer user-selectable (not enough peers yet), but if a
  // recipient's record or domain REQUIRES onion delivery the server enforces it, so
  // we still detect it and route accordingly.
  const [onion, setOnion] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const recipientInput = useRef<HTMLInputElement>(null);
  const bodyRef = useRef<HTMLTextAreaElement>(null);
  // Per-recipient classification (keyed by lowercased address) for the chip shields.
  const [recipientInfo, setRecipientInfo] = useState<Record<string, RecipientKind>>({});
  // The pinnable facts the directory served for each resolved recipient — both keys plus the
  // properties a pin covers, not just the signing key. Stored raw rather than as a precomputed
  // verdict: the comparison depends on the contact list, which loads asynchronously, so deriving
  // the verdict at render keeps it correct no matter which arrives first. Caching a verdict
  // computed during the lookup would silently miss a changed key whenever the lookup won the race
  // against contacts loading.
  const [recipientKeys, setRecipientKeys] = useState<Record<string, PinnedFacts>>({});

  // inspectRecipient resolves a recipient once: records whether it's a DMCN identity
  // or a legacy (non-DMCN) address, and turns on onion delivery when the record or its
  // domain requires it. The trusted-contact (blue) upgrade is applied at render time
  // from the contact list, so it appears the moment contacts load regardless of order.
  const inspectRecipient = async (addr: string) => {
    const key = addr.trim().toLowerCase();
    try {
      const rec = await lookupIdentity(addr);
      if (rec.require_onion) setOnion(true);
      // Two ways a directory says "no identity here", both handled: some answer a legacy
      // address by pointing at their own bridge (a 200 carrying legacy:true, where x25519_pub
      // describes the BRIDGE and not a correspondent), others simply 404 — see the catch below.
      // Either way the absence is recorded as an observation, because for a contact we have
      // already pinned, "the directory now offers no identity" is a change to compare, and a
      // blank leaves checkPin with nothing to say precisely when it matters most.
      setRecipientInfo(m => ({ ...m, [key]: rec.legacy ? 'legacy' : 'dmcn' }));
      if (rec.legacy) {
        setRecipientKeys(m => ({ ...m, [key]: absentIdentityFacts() }));
        return; // a bridge, not a correspondent — nothing to pin
      }

      // Record the facts while the recipient is being typed, so the warning can appear before the
      // message is written rather than after it is composed and the user is committed to sending.
      const facts = directoryFacts(rec);
      setRecipientKeys(m => ({ ...m, [key]: facts }));
      const contact = contactByAddress(addr);
      if (contact && !contact.ed25519Pub) {
        // First confirmed sighting of an existing contact's key — pin it, so a LATER swap is
        // detectable. pinKey is a no-op if this device already holds a pin for them.
        void pinKey(addr, facts);
      }
    } catch {
      // Not resolvable in the DMCN directory → a legacy address reachable only via a
      // bridge, which cannot be end-to-end encrypted. handleSend surfaces send errors.
      //
      // Record the ABSENCE as an observation rather than leaving it blank: for a contact we
      // have already pinned, "the directory now offers no identity" is a change to compare,
      // and a blank leaves checkPin with nothing to say precisely when it matters most.
      setRecipientInfo(m => ({ ...m, [key]: 'legacy' }));
      setRecipientKeys(m => ({ ...m, [key]: absentIdentityFacts() }));
    }
  };

  // Pre-filled (reply / reply-all) recipients may already require onion.
  useEffect(() => {
    to.forEach(r => void inspectRecipient(r));
    cc.forEach(r => void inspectRecipient(r));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one-shot on open: only the pre-filled recipients; later additions are inspected as they are entered
  }, []);

  // On a reply, drop the caret at the very top so the user types ABOVE the signature/quote.
  useEffect(() => {
    if (!replyTo) return;
    if (richMode) { editorRef.current?.focus(true); return; }
    const el = bodyRef.current;
    if (el) { el.focus(); el.setSelectionRange(0, 0); }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caret placement on open only; re-running on mode changes would yank the caret mid-edit
  }, []);

  // The settings doc syncs asynchronously, so it can land after the composer opened.
  // Both effects below re-seed only while the body is UNTOUCHED — a slow load must never
  // overwrite what the user has already typed.

  // Starting mode from the account preference (system default is rich).
  const modeApplied = useRef(false);
  useEffect(() => {
    if (modeApplied.current || settings.composePlainText === undefined) return;
    modeApplied.current = true;
    if (!dirtyRef.current) setRichMode(settings.composePlainText !== true);
  }, [settings.composePlainText]);

  // Prefill the composing signature. For a NEW message the signature goes at the top of an
  // empty body; for a REPLY it's spliced ABOVE the quoted original (top-posted).
  const sigApplied = useRef(false);
  useEffect(() => {
    if (sigApplied.current || !settings.signature) return;
    sigApplied.current = true;
    if (dirtyRef.current) return;
    setBody(plainScaffold(settings.signature));
    richInitial.current = htmlScaffold(settings.signature);
    editorRef.current?.setHTML(richInitial.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed on the setting alone by design: re-seeds once, only while the body is untouched
  }, [settings.signature]);

  // toggleMode converts the body rather than discarding it. The HTML is stashed so a
  // rich → plain → rich round-trip is lossless as long as the plain text wasn't edited;
  // once it has been, the edited text wins and the formatting is genuinely gone.
  const stashedHtml = useRef<string | null>(null);
  const toggleMode = () => {
    dirtyRef.current = true;
    if (richMode) {
      const html = editorRef.current?.getHTML() ?? '';
      stashedHtml.current = html;
      setBody(toPlainText(html));
      setRichMode(false);
      return;
    }
    const stash = stashedHtml.current;
    richInitial.current = stash !== null && toPlainText(stash) === body ? stash : fromPlainText(body);
    setRichMode(true);
  };

  // commitPending trims + de-dupes the field's pending text into its chip list and
  // returns the resulting list (so a send triggered before blur still sees it).
  const commitPending = (
    values: string[],
    setValues: (v: string[]) => void,
    pending: string,
    setPending: (s: string) => void,
  ): string[] => {
    const r = pending.trim().replace(/,$/, '').trim();
    setPending('');
    if (!r || values.includes(r)) return values;
    const next = [...values, r];
    setValues(next);
    void inspectRecipient(r);
    return next;
  };

  // pickRecipient commits an explicit address (a chosen contact suggestion) into a
  // field, clearing the pending text — the click/Enter analogue of commitPending.
  const pickRecipient = (
    values: string[],
    setValues: (v: string[]) => void,
    setPending: (s: string) => void,
  ) => (value: string) => {
    const r = value.trim();
    setPending('');
    if (!r || values.includes(r)) return;
    setValues([...values, r]);
    void inspectRecipient(r);
  };

  const fieldKeyHandler = (
    values: string[],
    setValues: (v: string[]) => void,
    pending: string,
    setPending: (s: string) => void,
  ) => (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commitPending(values, setValues, pending, setPending); }
    else if (e.key === 'Backspace' && pending === '' && values.length > 0) {
      setValues(values.slice(0, -1));
    }
  };

  // Inline images are attachments too — same sealed blob, same cap — but they're
  // referenced from the HTML body by cid: rather than listed for download, so the chip
  // strip shows only the real attachments.
  const fileAttachments = attachments.filter(a => a.disposition !== 'inline');
  const attachedBytes = attachments.reduce((n, a) => n + a.sizeBytes, 0);
  const usedBytes = () => attachmentsRef.current.reduce((n, a) => n + a.sizeBytes, 0);
  const capMessage = `Attachments can’t exceed ${Math.round(MAX_TOTAL_ATTACHMENT_BYTES / (1024 * 1024))} MB in total.`;

  const pushAttachments = (adds: AttachmentInput[]) => {
    attachmentsRef.current = [...attachmentsRef.current, ...adds];
    setAttachments(attachmentsRef.current);
  };

  // addFiles reads each selected file fully into memory, hashes it, and appends it as
  // an AttachmentInput. The whole batch is rejected (nothing added) if it would push
  // the running total past the cap, so the composer never holds an over-limit set.
  const addFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const additions: AttachmentInput[] = [];
    let running = usedBytes();
    for (const file of Array.from(files)) {
      const content = new Uint8Array(await file.arrayBuffer());
      running += content.length;
      if (running > MAX_TOTAL_ATTACHMENT_BYTES) {
        setError(capMessage);
        return;
      }
      const contentHash = new Uint8Array(await crypto.subtle.digest('SHA-256', content));
      additions.push({
        attachmentId: newUuid(),
        filename: file.name,
        contentType: file.type || 'application/octet-stream',
        sizeBytes: content.length,
        contentHash,
        content,
      });
    }
    setError('');
    pushAttachments(additions);
  };

  // addInlineImage backs the editor's image insert (toolbar / paste / drop): it stores the
  // bytes as an inline-disposition attachment and hands back the cid the body references,
  // plus a data: preview (the CSP allows data:, not blob:).
  const addInlineImage = async (file: File): Promise<InsertedImage | null> => {
    const content = new Uint8Array(await file.arrayBuffer());
    if (usedBytes() + content.length > MAX_TOTAL_ATTACHMENT_BYTES) {
      setError(capMessage);
      return null;
    }
    const contentHash = new Uint8Array(await crypto.subtle.digest('SHA-256', content));
    const contentType = file.type || 'application/octet-stream';
    const contentId = `${toHex(newUuid())}@dmcn`;
    const filename = file.name || 'image';
    pushAttachments([{
      attachmentId: newUuid(),
      filename,
      contentType,
      sizeBytes: content.length,
      contentHash,
      content,
      contentId,
      disposition: 'inline',
    }]);
    setError('');
    return { contentId, previewUrl: `data:${contentType};base64,${toBase64(content)}`, alt: filename };
  };

  const removeAttachment = (att: AttachmentInput) => {
    attachmentsRef.current = attachmentsRef.current.filter(a => a !== att);
    setAttachments(attachmentsRef.current);
  };

  const handleSend = async () => {
    if (!keys || !address) return;
    // Flush any un-committed pending text in each field first.
    const toList = pendingTo.trim() ? commitPending(to, setTo, pendingTo, setPendingTo) : to;
    const ccList = pendingCc.trim() ? commitPending(cc, setCc, pendingCc, setPendingCc) : cc;
    const bccList = pendingBcc.trim() ? commitPending(bcc, setBcc, pendingBcc, setPendingBcc) : bcc;
    if (toList.length === 0) { setError('Add at least one recipient.'); return; }

    // Every distinct address gets exactly one delivered copy; a person listed in
    // both To and Cc (etc.) is not sent twice.
    const allRecipients = [...new Set([...toList, ...ccList, ...bccList])];

    // Capture the non-null key handle + own address for the closure below — TS
    // narrowing from the guard above doesn't carry into a nested function.
    const k = keys;
    const selfAddress = address;

    // Encode, sign over the envelope hash, and STORE one envelope. The private key
    // never leaves the browser; the server only relays the signed bytes. recipient
    // is the registry address the relay routes to (the actual recipient, or our own
    // address for the Sent copy).
    // Stores one recipient copy and returns the relay-accept hash (envelope_hash)
    // for the Sent record's acceptHashes.
    const storeEnvelope = async (envelope: SplitEnvelope, recipient: string, viaOnion: boolean): Promise<string> => {
      const envBytes = await encodeSplitEnvelope(envelope);
      const envHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(envBytes)));
      const envSignature = await signWithKey(k.ed25519Sign, envHash);
      const res = await sendMessage({
        sender_address: selfAddress,
        sender_signature: toBase64(envSignature),
        envelope: toBase64(envBytes),
        recipient_address: recipient,
        onion: viaOnion,
        // Shared across every recipient copy of this compose, so send-cap enforcement
        // counts one message with N recipients rather than N separate messages.
        message_id: toHex(messageId),
      });
      return res.envelope_hash;
    };

    // One messageId/threadId/timestamp for the whole compose, shared across every
    // copy — this is what lets the Sent view collapse a multi-recipient send into a
    // single "To: a, b, c" row (grouped by messageId).
    const messageId = crypto.getRandomValues(new Uint8Array(16));
    messageId[6] = (messageId[6] & 0x0f) | 0x40;
    messageId[8] = (messageId[8] & 0x3f) | 0x80;
    // A reply continues the original thread and references it; a new compose starts a
    // fresh thread. Both ride the signed header (portable to the bridge as
    // In-Reply-To/References later). A pre-feature original has an all-zero threadId hex
    // → treat as absent and start fresh.
    const threadId = replyTo?.threadId && !/^0*$/.test(replyTo.threadId)
      ? fromHex(replyTo.threadId)
      : newUuid();
    const replyToId = replyTo?.replyToId ? fromHex(replyTo.replyToId) : undefined;
    const sentAt = Math.floor(Date.now() / 1000);

    // Derive both renderings ONCE, before the recipient loop, so every copy (recipients,
    // the bridge copy, and the Sent self-copy) carries byte-identical content.
    //
    // Sanitizing here is the point of the exercise: this is the boundary where composed
    // markup becomes wire bytes, and it's the last chance to ensure a hostile paste isn't
    // shipped under the sender's own signature. The plain-text part is always produced —
    // it stays the primary body, so text-only readers and the trust-gated plain-text peek
    // never see an empty message.
    let bodyHtml: string | undefined;
    let bodyText = body;
    if (richMode) {
      const clean = sanitizeOutgoing(editorRef.current?.getHTML() ?? '').html;
      const plain = toPlainText(clean);
      // An empty rich body is just an empty message — don't ship a hollow HTML part.
      if (plain.trim() || /<img\s/i.test(clean)) {
        bodyHtml = clean;
        bodyText = plain;
      } else {
        bodyText = '';
      }
    }

    // Inline images the user inserted and then deleted again are still in the attachment
    // list; drop the ones the final body doesn't reference so no orphan parts ride along.
    const referenced = new Set(Array.from(bodyHtml?.matchAll(/src="cid:([^"]*)"/g) ?? [], m => m[1]));
    const sendAttachments = attachmentsRef.current.filter(
      a => a.disposition !== 'inline' || referenced.has(a.contentId ?? '')
    );

    // Shared header fields. recipientAddress (per-copy routing label) and bcc are
    // filled in per copy below; to/cc are identical and visible everywhere.
    const common = {
      version: 1,
      messageId,
      threadId,
      replyToId,
      senderAddress: selfAddress,
      senderPublicKey: k.ed25519Public,
      senderSignKey: k.ed25519Sign,
      sentAt,
      subject,
      bodyText,
      bodyHtml,
      attachments: sendAttachments,
      to: toList,
      cc: ccList,
    };

    setLoading(true);
    setError('');
    try {
      // Route an outbound message to a LEGACY email recipient through the sender domain's bridge:
      // seal the SAME split envelope every other recipient gets, but wrap the CEK for the BRIDGE's
      // X25519 key and label it with the legacy address, then STORE it on the bridge. The bridge
      // decrypts, reads the real destination out of the signed header, and delivers over SMTP.
      // Not end-to-end encrypted to the recipient: the bridge sees the plaintext, by design.
      //
      // This used to seal the older whole-message (v1) form, and that shape has nowhere to put the
      // shared To/Cc — the audience lives on the split HEADER. So the bridge received no audience
      // for browser-composed mail and addressed each copy to its one recipient: a message to three
      // people arrived as three apparently-private messages, with nobody for Reply All to reach.
      // Sealing the same split envelope as everyone else fixes it at the source, and leaves one
      // sealing path for every recipient, legacy or not.

      // Deliver a copy to each recipient (DMCN natively, or via the legacy bridge on 404).
      for (const rcpt of allRecipients) {
        let recipient;
        try {
          recipient = await lookupIdentity(rcpt);
        } catch (e) {
          // No DMCN record for a well-formed email ⇒ a LEGACY recipient, reachable only if this
          // deployment has a way (see lib/deployment.ts sendToLegacy).
          if (e instanceof ApiError && e.status === 404 && rcpt.includes('@') && deployment.sendToLegacy) {
            // Unless we had verified a DMCN identity for them. Falling back to a bridge would
            // silently downgrade that correspondence to ordinary email, readable by the bridge
            // and every hop after it — and a fleet withholding one record produces exactly this.
            // Same refusal as a changed key, for the same reason: it is unrecoverable once sent.
            if (checkPin(contactByAddress(rcpt), absentIdentityFacts()) === 'changed') {
              throw new Error(pinnedIdentityGoneWarning(rcpt) + ' Confirm it in the warning above if that is expected.', { cause: e });
            }
            await deployment.sendToLegacy({
              recipient: rcpt,
              senderAddress: selfAddress,
              seal: async x25519Pub => encodeSplitEnvelope(await encryptSplit({
                ...common,
                recipientAddress: rcpt,
                bcc: [],
                recipients: [{ deviceId: new Uint8Array(16), x25519Pub }],
              })),
              sign: bytes => signWithKey(k.ed25519Sign, bytes),
            });
            continue;
          }
          throw e;
        }
        // Refuse rather than warn: the harm here is sealing a message to a key the recipient does
        // not hold, which is unrecoverable once sent. A pinned mismatch means either they rotated
        // (harmless, and re-verifying clears it) or someone else now holds the address — and we
        // cannot tell which from here, so the safe default is to stop.
        const observedFacts = directoryFacts(recipient);
        if (checkPin(contactByAddress(rcpt), observedFacts) === 'changed') {
          throw new Error(
            (observedFacts.noIdentity ? pinnedIdentityGoneWarning(rcpt) : pinnedKeyWarning(rcpt)) +
            ' Confirm it in the warning above if that is expected.',
          );
        }
        const recipientX25519 = fromBase64(recipient.x25519_pub);

        // Recipient copy: CEK wrapped only for them, STORE'd to their relay
        // (onion-routed when requested or required by their record). Bcc is EMPTY on
        // every recipient copy — a Bcc recipient is never revealed, and a reply-all
        // can't leak the Bcc list.
        await storeEnvelope(
          await encryptSplit({
            ...common,
            recipientAddress: rcpt,
            bcc: [],
            recipients: [{ deviceId: new Uint8Array(16), x25519Pub: recipientX25519 }],
          }),
          rcpt,
          onion,
        );
      }

      // Sent self-copy: seal the SAME composed message to our OWN X25519 key and store
      // the envelope (a small listed header + a lazy body) in the owner-only personal
      // store. Sent then renders through the normal header/body path — body, attachments,
      // HTML alternatives all live in the body, decrypted on open, exactly like inbox mail
      // — so the Sent list needs only the headers. Sealed to us alone, so it never touches
      // the relay STORE path, onion, or the free-ride guard (the full bcc audience rides on
      // this self-copy only). Best-effort: the message is already delivered, so a Sent-copy
      // failure must not fail the send.
      try {
        const selfEnvelope = await encryptSplit({
          ...common,
          recipientAddress: selfAddress,
          bcc: bccList,
          recipients: [{ deviceId: k.deviceId, x25519Pub: k.x25519Public }],
        });
        await new SentStore(k).putEnvelope(toHex(messageId), selfEnvelope);
      } catch (copyErr) {
        console.warn('Sent copy could not be saved (message delivered):', copyErr);
      }

      onSent?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };

  const inputReset = { border: 'none', outline: 'none', background: 'transparent', font: 'inherit' } as const;

  // Any legacy (non-DMCN) recipient means the message can't be end-to-end encrypted
  // for everyone — surfaced as a warning above the footer.
  const hasLegacy = [...to, ...cc, ...bcc].some(a => recipientInfo[a.trim().toLowerCase()] === 'legacy');
  // Whether any recipient resolved as a DMCN identity — the encryption banner only
  // makes sense (and is only accurate) when there's someone it can be encrypted to.
  const hasDmcn = [...to, ...cc, ...bcc].some(a => recipientInfo[a.trim().toLowerCase()] === 'dmcn');
  // Recipients whose key no longer matches the one we pinned. Sending to them is BLOCKED in
  // handleSend, so this banner is the explanation for a send that is about to be refused, not a
  // soft advisory — hence naming the addresses rather than a generic "some recipients".
  const changedKeyRecipients = [...to, ...cc, ...bcc]
    .map(a => a.trim())
    .filter(a => a && checkPin(contactByAddress(a), recipientKeys[a.toLowerCase()]) === 'changed');
  // Of those, the ones whose identity DISAPPEARED rather than changed keys. Same block, but a
  // different thing to tell the reader: nothing was swapped, the mail would simply leave the
  // network in the clear.
  const goneRecipients = changedKeyRecipients.filter(a => recipientKeys[a.toLowerCase()]?.noIdentity);
  const keySwapRecipients = changedKeyRecipients.filter(a => !recipientKeys[a.toLowerCase()]?.noIdentity);

  // confirmChange records the state the directory is showing NOW as the verified one, which is
  // what unblocks this recipient — permanently, until it changes again. It re-pins rather than
  // clearing: the point of confirming is to move the pin forward, not to stop watching.
  const confirmChange = async (addr: string) => {
    const observed = recipientKeys[addr.toLowerCase()];
    if (!observed) return;
    const existing = contactByAddress(addr);
    await allowlist({
      address: addr,
      name: existing?.name ?? '',
      fingerprint: existing?.fingerprint ?? '',
      // Keep however they were verified originally: confirming a rotation is not a reason to
      // forget that the key was once checked in person. Only a contact we have never held
      // falls back to the weakest provenance.
      provenance: existing?.provenance ?? 'user_approved',
      ...(observed.noIdentity
        ? { noIdentity: true }
        : {
            ed25519Pub: observed.ed25519Pub,
            x25519Pub: observed.x25519Pub,
            bridgeCapability: observed.bridgeCapability,
            adminKeyCustody: observed.adminKeyCustody,
          }),
    });
  };
  // Recipients whose KEYS still match but whose pinned properties moved. Not a send blocker: no
  // message is mis-sealed by it, so refusing would be the wrong trade. Still shown, because
  // adminKeyCustody flipping on is a domain asserting that an admin now holds this account's
  // keys — an operator-side change no key comparison can see.
  const changedRecordRecipients = [...to, ...cc, ...bcc]
    .map(a => a.trim())
    .filter(a => a && checkPin(contactByAddress(a), recipientKeys[a.toLowerCase()]) === 'record_changed');
  const changedRecordDetail = (() => {
    const first = changedRecordRecipients[0];
    if (!first) return '';
    const pinned = contactFacts(contactByAddress(first));
    const seen = recipientKeys[first.toLowerCase()];
    return pinned && seen ? changedFacts(pinned, seen).join(' and ') : '';
  })();

  // Full-screen sheet on mobile; floating window anchored bottom-right on desktop.
  const shell: CSSProperties = mobile
    ? {
        position: 'fixed', inset: 0, width: '100%', height: '100dvh', maxWidth: 'none', zIndex: 70,
        paddingTop: 'env(safe-area-inset-top)', paddingBottom: 'env(safe-area-inset-bottom)',
        background: 'var(--surface-card)', border: 'none', boxShadow: 'none',
        display: 'flex', flexDirection: 'column',
      }
    : {
        position: 'absolute', right: 'var(--space-6)', bottom: 0, width: 540, maxWidth: 'calc(100% - 32px)',
        background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderBottom: 'none',
        boxShadow: 'var(--shadow-md)', display: 'flex', flexDirection: 'column', zIndex: 40, maxHeight: 'calc(100% - 16px)',
      };

  return (
    <div style={shell}>
      {/* Title bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--space-3) var(--space-4)', background: 'var(--neutral-900)', color: 'var(--neutral-25)' }}>
        <span style={{ fontSize: 'var(--text-md)', fontWeight: 600 }}>{replyTo ? 'Reply' : 'New message'}</span>
        <button aria-label="Close" onClick={onClose} style={{ border: 'none', background: 'transparent', color: 'inherit', cursor: 'pointer', display: 'flex' }}>
          <Icon name="x" size={18} />
        </button>
      </div>

      {/* Recipients */}
      <RecipientField
        label="To"
        values={to}
        onRemove={r => setTo(to.filter(x => x !== r))}
        pending={pendingTo}
        setPending={setPendingTo}
        onKey={fieldKeyHandler(to, setTo, pendingTo, setPendingTo)}
        onBlur={() => commitPending(to, setTo, pendingTo, setPendingTo)}
        placeholder={to.length === 0 ? `name@${DEFAULT_DOMAIN}` : 'Add recipient'}
        mobile={mobile}
        inputRef={recipientInput}
        contacts={contacts}
        onPick={pickRecipient(to, setTo, setPendingTo)}
        recipientInfo={recipientInfo}
        nameFor={nameFor}
        rightSlot={!showCcBcc ? (
          <button
            type="button"
            onClick={e => { e.stopPropagation(); setShowCcBcc(true); }}
            style={{ border: 'none', background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 'var(--text-sm)', padding: '4px 0' }}
          >
            Cc/Bcc
          </button>
        ) : null}
      />
      {showCcBcc && (
        <>
          <RecipientField
            label="Cc"
            values={cc}
            onRemove={r => setCc(cc.filter(x => x !== r))}
            pending={pendingCc}
            setPending={setPendingCc}
            onKey={fieldKeyHandler(cc, setCc, pendingCc, setPendingCc)}
            onBlur={() => commitPending(cc, setCc, pendingCc, setPendingCc)}
            placeholder="Carbon copy"
            mobile={mobile}
            contacts={contacts}
            onPick={pickRecipient(cc, setCc, setPendingCc)}
            recipientInfo={recipientInfo}
            nameFor={nameFor}
          />
          <RecipientField
            label="Bcc"
            values={bcc}
            onRemove={r => setBcc(bcc.filter(x => x !== r))}
            pending={pendingBcc}
            setPending={setPendingBcc}
            onKey={fieldKeyHandler(bcc, setBcc, pendingBcc, setPendingBcc)}
            onBlur={() => commitPending(bcc, setBcc, pendingBcc, setPendingBcc)}
            placeholder="Blind carbon copy — hidden from other recipients"
            mobile={mobile}
            contacts={contacts}
            onPick={pickRecipient(bcc, setBcc, setPendingBcc)}
            recipientInfo={recipientInfo}
            nameFor={nameFor}
          />
        </>
      )}

      {/* Subject */}
      <div style={{ padding: '0 var(--space-4)', borderBottom: '1px solid var(--border-subtle)' }}>
        <input
          value={subject}
          onChange={e => setSubject(e.target.value)}
          placeholder="Subject"
          style={{ ...inputReset, width: '100%', fontSize: mobile ? 16 : 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', padding: 'var(--space-3) 0' }}
        />
      </div>

      {/* Body — rich by default; plain text is the per-message escape hatch. */}
      {richMode ? (
        <RichTextEditor
          ref={editorRef}
          initialHtml={richInitial.current}
          placeholder="Write something — it's encrypted before it leaves your device."
          mobile={mobile}
          onDirty={() => { dirtyRef.current = true; }}
          onInsertImage={addInlineImage}
        />
      ) : (
        <textarea
          ref={bodyRef}
          value={body}
          onChange={e => { dirtyRef.current = true; setBody(e.target.value); }}
          placeholder="Write something — it's encrypted before it leaves your device."
          style={{ ...inputReset, resize: 'none', fontSize: mobile ? 16 : 'var(--text-base)', lineHeight: 'var(--leading-relaxed)', color: 'var(--text-body)', padding: 'var(--space-4)', minHeight: mobile ? 0 : 200, flex: 1 }}
        />
      )}

      {/* Attachment chips (name · size), with a running total against the cap. Inline
          images are excluded — they're visible in the body itself — but their bytes
          still count towards the total shown here. */}
      {fileAttachments.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)' }}>
          {fileAttachments.map((a, i) => (
            <Tag key={i} onRemove={() => removeAttachment(a)}>
              <Icon name="paperclip" size={13} style={{ color: 'var(--text-muted)', flex: 'none' }} />
              <span title={a.filename} style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{truncateFilename(a.filename)}</span>
              <span style={{ color: 'var(--text-muted)', flex: 'none' }}>· {formatBytes(a.sizeBytes)}</span>
            </Tag>
          ))}
          <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            {formatBytes(attachedBytes)} of {Math.round(MAX_TOTAL_ATTACHMENT_BYTES / (1024 * 1024))} MB
          </span>
        </div>
      )}

      {/* Hidden picker; reset value so re-selecting the same file still fires onChange. */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={e => { void addFiles(e.target.files); e.target.value = ''; }}
      />

      {error && (
        <div style={{ padding: 'var(--space-2) var(--space-4)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{error}</div>
      )}

      {/* Changed-key warning. Ranked ABOVE the legacy and encryption banners because it is the
          only one that blocks sending, and because "end-to-end encrypted" sitting alone under a
          swapped key would be technically true and dangerously misleading. */}
      {changedKeyRecipients.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--danger-subtle)', color: 'var(--text-body)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger)', flex: 'none', marginTop: 2 }} />
            <span>
              {keySwapRecipients.length > 0 && (
                <>The signing key for {keySwapRecipients.join(', ')} has changed since you verified them.{' '}</>
              )}
              {goneRecipients.length > 0 && (
                <>{goneRecipients.join(', ')} no longer {goneRecipients.length === 1 ? 'has' : 'have'} a DMCN
                  identity, so mail would leave over a bridge as ordinary email.{' '}</>
              )}
              Sending is blocked until you confirm out of band. Confirming records what the directory
              shows now, and applies until it changes again.
            </span>
          </div>
          {/* One control per recipient: a compose to four people should not make you re-verify
              three of them to reach the one that changed. */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', paddingLeft: 23 }}>
            {changedKeyRecipients.map(a => (
              <Button key={a} size="sm" variant="secondary" leftIcon={<Icon name="shield-check" size={14} />}
                onClick={() => { void confirmChange(a); }}>
                Confirm {a}
              </Button>
            ))}
          </div>
        </div>
      )}

      {changedRecordRecipients.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--warning-subtle)', color: 'var(--text-body)' }}>
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none', marginTop: 2 }} />
          <span>
            The {changedRecordDetail || 'identity record'} for {changedRecordRecipients.join(', ')} changed
            since you verified them. Their keys are unchanged, so this message is still sealed to the same
            person — but the change was not something they signed.
          </span>
        </div>
      )}

      {/* Legacy-recipient warning: some recipients can't receive E2E-encrypted mail. */}
      {hasLegacy && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--warning-subtle)', color: 'var(--text-body)' }}>
          <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none' }} />
          Some recipients use legacy email and can't receive end-to-end encrypted messages.
        </div>
      )}

      {/* Encryption banner — only when there's a DMCN recipient to encrypt to. */}
      {hasDmcn && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--brand-subtle)', color: 'var(--brand-text)' }}>
          <Icon name="shield-check" size={15} style={{ color: 'var(--brand)' }} />
          End-to-end encrypted — only your DMCN recipients can read this.
        </div>
      )}

      {/* Footer */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-3) var(--space-4)', borderTop: '1px solid var(--border-subtle)' }}>
        <Button leftIcon={<Icon name="send" size={16} />} onClick={handleSend} disabled={loading}>
          {loading ? 'Sending…' : 'Send'}
        </Button>
        <IconButton aria-label="Attach files" onClick={() => fileInputRef.current?.click()} disabled={loading}>
          <Icon name="paperclip" />
        </IconButton>
        <IconButton
          aria-label={richMode ? 'Switch to plain text' : 'Switch to rich text'}
          title={richMode ? 'Plain text' : 'Rich text'}
          active={!richMode}
          onClick={toggleMode}
          disabled={loading}
        >
          <Icon name={richMode ? 'file' : 'pencil'} />
        </IconButton>
        <div style={{ flex: 1 }} />
        <IconButton aria-label="Discard" onClick={onClose}><Icon name="trash" /></IconButton>
      </div>
    </div>
  );
}

const fieldInputReset = { border: 'none', outline: 'none', background: 'transparent', font: 'inherit' } as const;

interface RecipientFieldProps {
  label: string;
  values: string[];
  onRemove: (r: string) => void;
  pending: string;
  setPending: (s: string) => void;
  onKey: (e: KeyboardEvent<HTMLInputElement>) => void;
  onBlur: () => void;
  placeholder: string;
  mobile: boolean;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  rightSlot?: ReactNode;
  /** Address book, for type-ahead suggestions. */
  contacts: Contact[];
  /** Commit a chosen suggestion's address into the field. */
  onPick: (value: string) => void;
  /** Per-recipient classification (lowercased address → kind) for the chip shields. */
  recipientInfo: Record<string, RecipientKind>;
  /** Shared display-name resolver (contact name, else the address). */
  nameFor: (address: string) => string;
}

const MAX_SUGGESTIONS = 6;

/** A chip-list recipient input row (To / Cc / Bcc share this), with contact type-ahead. */
function RecipientField({ label, values, onRemove, pending, setPending, onKey, onBlur, placeholder, mobile, inputRef, rightSlot, contacts, onPick, recipientInfo, nameFor }: RecipientFieldProps) {
  const localRef = useRef<HTMLInputElement>(null);
  const ref = inputRef ?? localRef;
  const [focused, setFocused] = useState(false);
  const [activeIdx, setActiveIdx] = useState(0);

  const q = pending.trim().toLowerCase();
  const suggestions = q
    ? contacts
        .filter(c => !values.includes(c.address) && `${c.name} ${c.address}`.toLowerCase().includes(q))
        .slice(0, MAX_SUGGESTIONS)
    : [];
  const open = focused && suggestions.length > 0;

  // Reset the highlighted row whenever the query changes.
  useEffect(() => { setActiveIdx(0); }, [pending]);

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (open) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, suggestions.length - 1)); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, 0)); return; }
      if (e.key === 'Enter') {
        const pick = suggestions[activeIdx];
        if (pick) { e.preventDefault(); onPick(pick.address); return; }
      }
      if (e.key === 'Escape') { e.preventDefault(); setFocused(false); return; }
    }
    onKey(e);
  };

  return (
    <div
      onClick={() => ref.current?.focus()}
      style={{ position: 'relative', padding: 'var(--space-3) var(--space-4)', borderBottom: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', cursor: 'text' }}
    >
      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', minWidth: 24 }}>{label}</span>
      {values.map(r => {
        const key = r.trim().toLowerCase();
        const info = recipientInfo[key];
        const isContact = contacts.some(c => c.address.trim().toLowerCase() === key);
        // Legacy always wins (can't be E2E); otherwise a known contact is "trusted"
        // (blue), a resolvable non-contact is "dmcn" (green), unresolved is pending.
        const kind: RecipientKind | undefined = info === 'legacy' ? 'legacy' : isContact ? 'trusted' : info;
        const chip = recipientChip(kind);
        return (
          <Tag key={r} onRemove={() => onRemove(r)}>
            <Icon name={chip.icon} size={13} style={{ color: chip.color }} title={chip.title} />
            <span title={r}>{nameFor(r)}</span>
          </Tag>
        );
      })}
      <input
        ref={ref}
        value={pending}
        onChange={e => setPending(e.target.value)}
        onKeyDown={handleKeyDown}
        onFocus={() => setFocused(true)}
        onBlur={() => { setFocused(false); onBlur(); }}
        type="email"
        inputMode="email"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        role="combobox"
        aria-expanded={open}
        aria-autocomplete="list"
        placeholder={placeholder}
        style={{ ...fieldInputReset, flex: 1, minWidth: 80, fontSize: mobile ? 16 : 'var(--text-md)', color: 'var(--text-strong)', padding: '4px 0' }}
      />
      {rightSlot}

      {open && (
        <ul
          role="listbox"
          style={{
            position: 'absolute', top: '100%', left: 0, right: 0, margin: 0, padding: 'var(--space-1)', listStyle: 'none',
            background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-md)', zIndex: 10, maxHeight: 240, overflowY: 'auto',
          }}
        >
          {suggestions.map((c, i) => (
            <li
              key={c.address}
              role="option"
              aria-selected={i === activeIdx}
              // preventDefault on mousedown keeps input focus so onBlur doesn't commit
              // the raw pending text before the click selects the suggestion.
              onMouseDown={e => e.preventDefault()}
              onClick={() => onPick(c.address)}
              onMouseEnter={() => setActiveIdx(i)}
              style={{
                display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2)',
                borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                background: i === activeIdx ? 'var(--surface-hover)' : 'transparent',
              }}
            >
              <div style={{ minWidth: 0, flex: 1 }}>
                {nameFor(c.address) !== c.address && (
                  <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{nameFor(c.address)}</div>
                )}
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.address}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
