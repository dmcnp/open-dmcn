import type { ComposeReplyTo } from '../lib/compose';
import { deployment } from '@deployment';
import type { AccountIdentity } from '../lib/deployment';
import { useState, useRef, useEffect } from 'react';
import type { CSSProperties, ReactNode, KeyboardEvent } from 'react';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { lookupIdentity, sendMessage, ApiError, type IdentityLookupResponse } from '../lib/api/client';
import { absentIdentityFacts, checkPin, changedFacts, contactFacts, directoryFacts, pinnedIdentityGoneWarning, pinnedKeyWarning, type PinnedFacts } from '../lib/trust/pinnedKey';
import { loadKeyChange, type KeyChange } from '../lib/trust/lineage';
import { encryptSplit, type SplitEnvelope, type AttachmentInput } from '../lib/crypto/split';
import { encodeSplitEnvelope } from '../lib/crypto/protobuf';
import { signWithKey } from '../lib/crypto/sign';
import { toBase64, fromBase64, toHex, fromHex } from '../lib/crypto/keys';
import { deviceSendProof } from '../lib/crypto/deviceKey';
import { SentStore } from '../lib/api/sentStore';
import { DraftConflictError, NEW_DRAFT_BASE, draftHasContent, inlinePreviews, newDraftId, replySubject, type DraftBase, type DraftContent, type LoadedDraft } from '../lib/api/draftStore';
import { useDrafts } from '../lib/hooks/useDrafts';
import { SaveScheduler } from '../lib/draftAutosave';
import { setDraftPutAway } from '../lib/draftOpen';
import { useSettings } from '../lib/hooks/useSettings';
import { useContacts, type Contact } from '../lib/hooks/useContacts';
import { DEFAULT_DOMAIN } from '../lib/config';
import { Button, IconButton, Tag } from '../ds';
import { Icon } from './Icon';
import { ConfirmTrashButton } from './ConfirmTrashButton';
import { RichTextEditor, type RichTextEditorHandle, type InsertedImage } from './RichTextEditor';
import { sanitizeOutgoing } from '../lib/html/sanitize';
import { toPlainText } from '../lib/html/toPlainText';
import { fromPlainText } from '../lib/html/fromPlainText';
import { bufferSource } from '../lib/crypto/bytes';
import { formatBytes } from '../lib/format';
import { isRecipientClosed, lookupFailureKind, recipientClosedMessage } from '../lib/recipientLookup';
import {
  forwardFailedMessage, forwardNotice, forwardOnlyFailedMessage, forwardUnsendableNotice, forwardedOnlyMessage,
  planForwardCopies, type ForwardTargetKind,
} from '../lib/forwarding';


// Total attachment cap per message (body + all attachments ride inline in one sealed
// blob). ~25 MB: works with the existing size-class padding (rounds to whole MB above
// 1 MB) and stays reasonable for browser memory + the relay's in-memory store.
const MAX_TOTAL_ATTACHMENT_BYTES = 25 * 1024 * 1024;

// How long putting a draft away waits for the relay to take it before settling for the device copy.
const PUT_AWAY_WAIT_MS = 8000;

// within resolves true if p settles successfully inside ms, false if it fails or takes longer.
function within(p: Promise<void>, ms: number): Promise<boolean> {
  return new Promise(resolve => {
    const timer = window.setTimeout(() => resolve(false), ms);
    p.then(() => { window.clearTimeout(timer); resolve(true); }, () => { window.clearTimeout(timer); resolve(false); });
  });
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
//  - unchecked: the directory could not be asked just now      → muted, no claim either way
type RecipientKind = 'trusted' | 'dmcn' | 'legacy' | 'unchecked';

function recipientChip(kind: RecipientKind | undefined): {
  icon: 'shield-check' | 'shield' | 'alert-triangle';
  color: string;
  title: string;
} {
  switch (kind) {
    case 'trusted': return { icon: 'shield-check', color: 'var(--trust-contact)', title: 'Trusted contact' };
    case 'dmcn':    return { icon: 'shield-check', color: 'var(--trust-dmcn)', title: 'DMCN recipient — end-to-end encrypted' };
    case 'legacy':  return { icon: 'alert-triangle', color: 'var(--warning)', title: 'Legacy email — cannot be end-to-end encrypted' };
    case 'unchecked': return { icon: 'shield', color: 'var(--text-muted)', title: "We couldn't check this address just now." };
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
  /** A saved draft to carry on with. Its reply context arrives as replyTo, as for a fresh reply. */
  draft?: LoadedDraft | null;
  /** Open the other device's copy of this draft in place of this one (after a save conflict). */
  onReopenDraft?: (id: string) => void;
}

/**
 * Floating in-page compose window (the design's Compose pattern). Rendered inside
 * the inbox main column rather than as a standalone route. All crypto happens here
 * in the browser; the private key never leaves it.
 */
export function ComposeDialog({ onClose, replyTo = null, onSent, mobile = false, draft = null, onReopenDraft }: ComposeDialogProps) {
  const { address } = useAuth();
  const { keys } = useKeys();
  const { settings } = useSettings();
  const { contacts, nameFor, contactByAddress, pinKey, allowlist } = useContacts();
  // A saved draft, when this composer carries one on; everything below starts from it instead of
  // the reply or the account's defaults.
  const d = draft?.content;

  // Three recipient classes with standard email semantics. To/Cc are visible to
  // everyone; Bcc is only recorded on the sender's own Sent copy (see handleSend).
  const [to, setTo] = useState<string[]>(d?.to ?? replyTo?.to ?? []);
  const [cc, setCc] = useState<string[]>(d?.cc ?? replyTo?.cc ?? []);
  const [bcc, setBcc] = useState<string[]>(d?.bcc ?? []);

  // Which of our addresses this goes out as. Only a choice on a deployment with aliases (see
  // deployment.senderAddresses); otherwise it is the signed-in address and no row is shown. A
  // reply goes out as the alias the other side wrote to, and that alias is not kept as a
  // recipient: the reader could only strip the signed-in address, since it does not know the rest.
  const [senders, setSenders] = useState<AccountIdentity[]>([]);
  const [from, setFrom] = useState<string>(d?.from || address || '');
  useEffect(() => {
    if (!deployment.identities || !address || !keys) return;
    let cancelled = false;
    deployment.identities(keys).then(list => {
      if (cancelled) return;
      // A retired address cannot send: its record no longer resolves, so the relay would refuse
      // the STORE anyway. Leaving it in the row would offer a choice that always fails.
      setSenders(list.filter(a => !a.retiredAt));
      const ours = new Set(list.map(a => a.address.toLowerCase()));
      const reached = (replyTo?.sentTo ?? []).map(a => a.toLowerCase()).find(a => ours.has(a));
      // A draft already went through this when it was a fresh reply, and its From is the one chosen.
      if (reached && !d) {
        setFrom(reached);
        setTo(prev => prev.filter(a => !ours.has(a.toLowerCase())));
        setCc(prev => prev.filter(a => !ours.has(a.toLowerCase())));
      }
    }).catch(() => { /* no From row; the signed-in address sends */ });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- replyTo is fixed for the dialog's life
  }, [address, keys]);
  const [pendingTo, setPendingTo] = useState(d?.pending.to ?? '');
  const [pendingCc, setPendingCc] = useState(d?.pending.cc ?? '');
  const [pendingBcc, setPendingBcc] = useState(d?.pending.bcc ?? '');
  // Reveal Cc/Bcc up front when a Reply All prefilled Cc recipients.
  const [showCcBcc, setShowCcBcc] = useState(d ? d.showCcBcc : !!replyTo?.cc?.length);
  const [subject, setSubject] = useState(d ? d.subject : replySubject(replyTo?.subject ?? ''));

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
  const [richMode, setRichMode] = useState(() => (d ? d.rich : settings.composePlainText !== true));
  const [body, setBody] = useState(() => (d ? d.text : plainScaffold(settings.signature ?? '')));
  const editorRef = useRef<RichTextEditorHandle>(null);
  // The editor is uncontrolled and reads this only when it mounts, so it doubles as the
  // seed for a plain → rich switch (which is exactly when it mounts). A draft's HTML is the
  // owner's own, but it comes back from storage, so it passes the same sanitizer as a paste before
  // it reaches the editor's DOM; its inline images are then put back on screen from their bytes.
  const richInitial = useRef(d
    ? (d.rich ? inlinePreviews(sanitizeOutgoing(d.html).html, d.attachments) : '')
    : htmlScaffold(settings.signature ?? ''));
  // Set once the user edits either body, so a late-loading settings doc never clobbers it.
  const dirtyRef = useRef(!!d);

  // Attachments ride inline in the sealed body blob (one CEK). Read fully into memory
  // here; the crypto layer already round-trips AttachmentInput end-to-end. The ref is
  // authoritative because images are inserted from async handlers that would otherwise
  // read a stale `attachments` closure mid-batch.
  const [attachments, setAttachments] = useState<AttachmentInput[]>(d?.attachments ?? []);
  const attachmentsRef = useRef<AttachmentInput[]>(d?.attachments ?? []);
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
  // What the directory can prove about a changed key, per recipient (trust/lineage.ts).
  const [keyChanges, setKeyChanges] = useState<Record<string, KeyChange>>({});
  // Each recipient's owner-signed forwarding address, and what it turned out to be, so the notice
  // above Send can say whether that copy stays end-to-end encrypted (lib/forwarding.ts).
  const [forwardInfo, setForwardInfo] = useState<Record<string, { target: string; kind: ForwardTargetKind; unsendable?: boolean }>>({});
  // What happened that the sender should know once the message is sent (a recipient reached only
  // through their forward, a forward copy that did not go). Set ⇒ the dialog stays open on a
  // report instead of closing, and cannot send again.
  const [sentReport, setSentReport] = useState<SentReportItem[] | null>(null);
  const [savedContacts, setSavedContacts] = useState<Record<string, boolean>>({});

  // inspectForward records a recipient's forwarding address and looks it up, as a sender's client
  // will at Send: a DMCN identity gets an end-to-end copy, anything else an ordinary-email one.
  const inspectForward = async (key: string, target?: string) => {
    if (!target) {
      setForwardInfo(m => {
        if (!(key in m)) return m;
        const next = { ...m };
        delete next[key];
        return next;
      });
      return;
    }
    setForwardInfo(m => ({ ...m, [key]: { target, kind: 'unknown' } }));
    let kind: ForwardTargetKind = 'unknown';
    // Ordinary email goes out the way any legacy recipient's does: a directory that names its
    // bridge (legacy:true) is sealed to that bridge, and a 404 needs this deployment's own path.
    let unsendable = false;
    try {
      const t = await lookupIdentity(target);
      kind = t.legacy ? 'email' : 'dmcn';
    } catch (e) {
      kind = lookupFailureKind(e) === 'legacy' ? 'email' : 'unknown';
      unsendable = kind === 'email' && !deployment.sendToLegacy;
    }
    setForwardInfo(m => (m[key]?.target === target ? { ...m, [key]: { target, kind, unsendable } } : m));
  };

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
        void inspectForward(key, undefined);
        return; // a bridge, not a correspondent — nothing to pin
      }
      void inspectForward(key, rec.forward_to);

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
    } catch (e) {
      // Only a 404 says "no DMCN identity here": a legacy address reachable only via a bridge,
      // which cannot be end-to-end encrypted. Record that ABSENCE as an observation rather than
      // leaving it blank: for a contact we have already pinned, "the directory now offers no
      // identity" is a change to compare, and a blank leaves checkPin with nothing to say
      // precisely when it matters most.
      //
      // Any other failure means the directory could not be asked, which says nothing about the
      // address, so it records no facts (an outage must not read as "their identity is gone").
      // handleSend looks again and surfaces its own error.
      const kind = lookupFailureKind(e);
      setRecipientInfo(m => ({ ...m, [key]: kind }));
      if (kind === 'legacy') setRecipientKeys(m => ({ ...m, [key]: absentIdentityFacts() }));
      void inspectForward(key, undefined);
    }
  };

  // Pre-filled (reply / reply-all) recipients may already require onion.
  useEffect(() => {
    to.forEach(r => void inspectRecipient(r));
    cc.forEach(r => void inspectRecipient(r));
    bcc.forEach(r => void inspectRecipient(r));
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one-shot on open: only the pre-filled recipients; later additions are inspected as they are entered
  }, []);

  // On a reply, drop the caret at the very top so the user types ABOVE the signature/quote. A draft
  // was already under way, and the top is not where it was left.
  useEffect(() => {
    if (!replyTo || d) return;
    if (richMode) { editorRef.current?.focus(true); return; }
    const el = bodyRef.current;
    if (el) { el.focus(); el.setSelectionRange(0, 0); }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caret placement on open only; re-running on mode changes would yank the caret mid-edit
  }, []);

  // The settings doc syncs asynchronously, so it can land after the composer opened.
  // Both effects below re-seed only while the body is UNTOUCHED — a slow load must never
  // overwrite what the user has already typed.

  // Starting mode from the account preference (system default is rich).
  const modeApplied = useRef(!!d);
  useEffect(() => {
    if (modeApplied.current || settings.composePlainText === undefined) return;
    modeApplied.current = true;
    if (!dirtyRef.current) setRichMode(settings.composePlainText !== true);
  }, [settings.composePlainText]);

  // Prefill the composing signature. For a NEW message the signature goes at the top of an
  // empty body; for a REPLY it's spliced ABOVE the quoted original (top-posted).
  const sigApplied = useRef(!!d);
  useEffect(() => {
    if (sigApplied.current || !settings.signature) return;
    sigApplied.current = true;
    if (dirtyRef.current) return;
    scaffold.current = { plain: plainScaffold(settings.signature), html: htmlScaffold(settings.signature) };
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
    markEdited();
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
    markEdited();
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
      markEdited();
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
    markEdited();
    attachmentsRef.current = attachmentsRef.current.filter(a => a !== att);
    setAttachments(attachmentsRef.current);
  };

  // --- Drafts ---------------------------------------------------------------------------------
  //
  // The message is saved as a draft while it is written (api/draftStore.ts): to this device about
  // half a second after each change, and to the owner's personal store on the relay a few seconds
  // after typing pauses (and at least every 15 s while it does not), sealed to the owner so the same
  // draft opens on their other devices. Nothing is saved until someone changes something, and a new
  // message is not saved until it holds something worth keeping, so opening the composer and
  // closing it again leaves nothing behind. Sending removes the draft; Discard (clicked twice) deletes it; closing
  // keeps it.
  const { store: draftsStore, refreshDrafts, setOpen: setDraftOpenId } = useDrafts();
  // The store of the account this composer was opened on, kept even if the provider moves on.
  const draftStoreRef = useRef(draftsStore);
  if (!draftStoreRef.current && draftsStore) draftStoreRef.current = draftsStore;
  const draftIdRef = useRef<string | null>(draft?.id ?? null);
  const baseRef = useRef<DraftBase>(draft?.base ?? NEW_DRAFT_BASE);
  // Set once the person changes anything. Prefills arriving on their own (a signature, the From
  // a reply resolves to) are not a reason to save.
  const editedRef = useRef(false);
  // Set once this composer is finished with its draft: sent, discarded, or handed to another copy.
  const doneRef = useRef(false);
  // A save found another device's newer copy; saving waits for the person to choose.
  const conflictRef = useRef(false);
  // What the body is before anyone types: a new draft that still says only this is not kept.
  const scaffold = useRef(d ? { plain: '', html: '' } : { plain: plainScaffold(settings.signature ?? ''), html: htmlScaffold(settings.signature ?? '') });
  // The editor's last HTML, for a save made after the editor itself has gone (the shell closed).
  const lastHtml = useRef(d?.html ?? '');
  type SaveState = 'idle' | 'saving' | 'saved' | 'device' | 'failed' | 'full' | 'conflict' | 'gone';
  const [saveState, setSaveState] = useState<SaveState>(draft ? 'saved' : 'idle');
  // Saves run from timers, after the render that scheduled them: they read the message from here.
  const latest = useRef({ to, cc, bcc, from, subject, body, richMode, pendingTo, pendingCc, pendingBcc, showCcBcc });
  latest.current = { to, cc, bcc, from, subject, body, richMode, pendingTo, pendingCc, pendingBcc, showCcBcc };

  const currentContent = (): DraftContent => {
    const l = latest.current;
    let text = l.body;
    let html = '';
    if (l.richMode) {
      const live = editorRef.current?.getHTML();
      if (live !== undefined) lastHtml.current = live;
      html = lastHtml.current;
      text = toPlainText(html);
    }
    return {
      from: l.from || address || '', to: l.to, cc: l.cc, bcc: l.bcc,
      pending: { to: l.pendingTo, cc: l.pendingCc, bcc: l.pendingBcc }, showCcBcc: l.showCcBcc,
      subject: l.subject, rich: l.richMode, text, html,
      // The quote is already in the body; what is kept is what threading and From need.
      replyTo: replyTo ? { ...replyTo, quote: undefined, quoteHtml: undefined } : null,
      attachments: attachmentsRef.current,
    };
  };
  const untouchedText = () => (latest.current.richMode ? toPlainText(scaffold.current.html) : scaffold.current.plain);

  // What to save now, or null when there is nothing to save. The draft gets its id here, the first
  // time it holds something.
  const snapshot = (): { id: string; content: DraftContent; at: number } | null => {
    if (!editedRef.current || doneRef.current) return null;
    const content = currentContent();
    if (!draftIdRef.current) {
      if (!draftHasContent(content, untouchedText())) return null;
      draftIdRef.current = newDraftId();
      setDraftOpenId(draftIdRef.current, true);
    }
    return { id: draftIdRef.current, content, at: Date.now() };
  };

  const [deviceSaver] = useState(() => new SaveScheduler(async () => {
    const st = draftStoreRef.current;
    const snap = snapshot();
    if (!st || !snap) return;
    await st.saveLocal(snap.id, snap.content, baseRef.current, snap.at);
  }, 500, 2000));

  const [relaySaver] = useState(() => new SaveScheduler(async () => {
    const st = draftStoreRef.current;
    if (!st || conflictRef.current) return;
    const snap = snapshot();
    if (!snap) return;
    const created = baseRef.current.head === 0;
    setSaveState('saving');
    try {
      baseRef.current = await st.save(snap.id, snap.content, baseRef.current, snap.at);
      await st.clearLocal(snap.id, snap.at).catch(() => undefined);
      setSaveState('saved');
      if (created) void refreshDrafts();
    } catch (err) {
      if (err instanceof DraftConflictError) {
        conflictRef.current = true;
        setSaveState((await st.isStored(snap.id).catch(() => true)) ? 'conflict' : 'gone');
        return;
      }
      setSaveState(err instanceof ApiError && err.status === 507 ? 'full' : st.keepsLocal ? 'device' : 'failed');
      throw err;
    }
  }, 3000, 15000));

  const markEdited = () => {
    editedRef.current = true;
    deviceSaver.touch();
    relaySaver.touch();
  };

  // Any change to the message, once someone has started changing it. The rich body has no state
  // here; its keystrokes reach markEdited through the input events the composer captures.
  useEffect(() => {
    if (!editedRef.current) return;
    deviceSaver.touch();
    relaySaver.touch();
  }, [deviceSaver, relaySaver, to, cc, bcc, from, subject, body, richMode, pendingTo, pendingCc, pendingBcc, showCcBcc, attachments]);

  // Leaving the page, or the app going to the background, saves at once rather than on the timer,
  // which may not get to run. So does the composer going away without being put away (the shell
  // closed it: signed out, locked).
  useEffect(() => {
    const saveAll = () => {
      deviceSaver.flush().catch(() => undefined);
      relaySaver.flush().catch(() => undefined);
    };
    const onVisibility = () => { if (document.visibilityState === 'hidden') saveAll(); };
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', saveAll);
    if (draftIdRef.current) setDraftOpenId(draftIdRef.current, true);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', saveAll);
      saveAll();
      if (draftIdRef.current) setDraftOpenId(draftIdRef.current, false);
    };
  }, [deviceSaver, relaySaver, setDraftOpenId]);

  // Close and remove the draft: discarded, or sent. Saves already under way finish first, so none
  // of them lands after the delete and brings it back.
  const removeDraft = async () => {
    doneRef.current = true;
    await Promise.all([deviceSaver.abandon(), relaySaver.abandon()]);
    const id = draftIdRef.current;
    const st = draftStoreRef.current;
    if (!id || !st) return;
    setDraftOpenId(id, false);
    try {
      await st.delete(id);
    } catch (err) {
      console.warn('Draft could not be deleted:', err);
    }
    void refreshDrafts();
  };

  const handleDiscard = () => {
    onClose();
    void removeDraft();
  };

  // Save and close. True when the message was kept somewhere it will survive (or held nothing worth
  // keeping), false when it could not be: the composer then stays open and says so.
  //
  // With a device copy the window closes as soon as that is written, and the relay save is then
  // waited for (briefly) before this resolves, because what usually follows is an account switch:
  // a save still running after it would sign in as one account and present the other's session.
  // After that the timers stop; whatever did not reach the relay is in the device copy, which the
  // Drafts list uploads the next time this account is open (DraftStore.settleLocal).
  const putAway = async (): Promise<boolean> => {
    // Nothing changed since it was opened (or it is already sent): nothing to save.
    if (doneRef.current || !editedRef.current) { onClose(); return true; }
    if (!draftHasContent(currentContent(), untouchedText())) {
      // Emptied out, or never held anything: not a draft worth keeping.
      handleDiscard();
      return true;
    }
    let kept = false;
    if (draftStoreRef.current?.keepsLocal) {
      try {
        await deviceSaver.flush();
        kept = true;
        onClose();
      } catch { /* this device could not keep it: the relay is all there is */ }
    }
    const reached = await within(relaySaver.flush(), PUT_AWAY_WAIT_MS) && !conflictRef.current;
    if (!kept && !reached) {
      setError("This draft couldn't be saved. Check your connection and try again, or discard it.");
      return false;
    }
    deviceSaver.dispose();
    relaySaver.dispose();
    if (!kept) onClose();
    void refreshDrafts();
    return true;
  };
  const putAwayRef = useRef(putAway);
  putAwayRef.current = putAway;
  useEffect(() => {
    setDraftPutAway(() => putAwayRef.current());
    return () => setDraftPutAway(null);
  }, []);

  // After a conflict: overwrite the other copy with this one (or bring this one back, if the other
  // was sent or deleted), or open the other copy instead of this one.
  const keepThisCopy = async () => {
    const st = draftStoreRef.current;
    conflictRef.current = false;
    const snap = snapshot();
    if (!st || !snap) return;
    setSaveState('saving');
    try {
      baseRef.current = await st.save(snap.id, snap.content, NEW_DRAFT_BASE, snap.at, true);
      await st.clearLocal(snap.id, snap.at).catch(() => undefined);
      setSaveState('saved');
      void refreshDrafts();
    } catch {
      setSaveState(st.keepsLocal ? 'device' : 'failed');
      relaySaver.touch();
    }
  };
  const openOtherCopy = async () => {
    const id = draftIdRef.current;
    if (!id || !onReopenDraft) return;
    doneRef.current = true;
    await Promise.all([deviceSaver.abandon(), relaySaver.abandon()]);
    await draftStoreRef.current?.clearLocal(id).catch(() => undefined);
    onReopenDraft(id);
  };

  const saveLabel = saveState === 'saving' ? 'Saving…'
    : saveState === 'saved' ? 'Draft saved'
    : saveState === 'device' ? 'Saved on this device'
    : saveState === 'failed' ? 'Not saved'
    : saveState === 'full' ? 'Not saved: your storage is full'
    : '';

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
    // `k` is whoever this goes out AS: the chosen identity's keys (an isolated alias signs
    // with its own derived key; a shared one with the account's), or the account's.
    const selfAddress = from || address;
    const k = senders.find(a => a.address.toLowerCase() === selfAddress.toLowerCase())?.keys ?? keys;

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
        // The device belongs to the ACCOUNT, also when this goes out as an alias.
        ...(await deviceSendProof(address, envHash)),
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

      const sendViaBridge = (rcpt: string) => deployment.sendToLegacy!({
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

      // A forward copy (lib/forwarding.ts): the forwarding address is resolved now, as every send
      // does, so one that has gained a DMCN identity since the forward was set gets an end-to-end
      // copy. Built like a Bcc copy — its own recipient_address, the message's own To/Cc — so the
      // target's reader passes its audience check. Its own forward is never followed. A failure is
      // reported after the send rather than failing it: the recipient's own copy is what they asked
      // for, the forward is theirs to arrange. Returns the target's record when it is a DMCN one.
      const sendForwardCopy = async (target: string): Promise<{ ok: boolean; rec?: IdentityLookupResponse }> => {
        try {
          let trec: IdentityLookupResponse | undefined;
          try {
            trec = await lookupIdentity(target);
          } catch (e) {
            if (lookupFailureKind(e) !== 'legacy') throw e;
          }
          if (!trec) {
            if (!deployment.sendToLegacy) return { ok: false };
            await sendViaBridge(target);
            return { ok: true };
          }
          // A DMCN identity, or a directory's legacy:true answer naming the bridge to seal to (the
          // reference daemon's): either way sealed to the key the lookup gave, as the recipient
          // loop below does. Only a real identity is offered as a contact afterwards.
          await storeEnvelope(
            await encryptSplit({
              ...common,
              recipientAddress: target,
              bcc: [],
              recipients: [{ deviceId: new Uint8Array(16), x25519Pub: fromBase64(trec.x25519_pub) }],
            }),
            target,
            onion || !!trec.require_onion,
          );
          return { ok: true, rec: trec.legacy ? undefined : trec };
        } catch (e) {
          console.warn('forward copy not sent:', e);
          return { ok: false };
        }
      };
      const reports: SentReportItem[] = [];
      // Addresses that get this message anyway, so no forward copy duplicates one.
      const reached = new Set([...allRecipients, selfAddress].map(a => a.trim().toLowerCase()));

      // Deliver a copy to each recipient (DMCN natively, or via the legacy bridge on 404).
      for (const rcpt of allRecipients) {
        let recipient;
        try {
          recipient = await lookupIdentity(rcpt);
        } catch (e) {
          // No DMCN record for a well-formed email ⇒ a LEGACY recipient, reachable only if this
          // deployment has a way (see lib/deployment.ts sendToLegacy).
          if (e instanceof ApiError && e.status === 404 && rcpt.includes('@') && deployment.sendToLegacy) {
            // A recipient we had verified as a DMCN identity who now resolves to nothing is a
            // downgrade: the message leaves as ordinary email, readable by the bridge and every
            // service after it, and a fleet withholding one record produces exactly this signal.
            // Disclosed in the composer (pinnedIdentityGoneWarning) and NOT refused here — see
            // the note on the changed-key case below.
            await sendViaBridge(rcpt);
            continue;
          }
          throw e;
        }
        // A changed key is DISCLOSED, never refused. This used to throw, on the reasoning that
        // sealing a message to a key the recipient may not hold is unrecoverable once sent — true,
        // and still the reason the banner is red and names every affected address. What it is not
        // is ours to decide. The same principle that made a rotation stop being applied silently
        // (whitepaper §14.1.2, amended) says the person who pinned the key chooses what to do
        // about it; refusing on their behalf tells them their judgement is not wanted, and teaches
        // them that the warning is an obstacle rather than information.
        //
        // So the composer's job is to make the risk and the safe order impossible to miss before
        // Send is pressed, which is what the banner above the footer does, per recipient, with the
        // evidence the directory could actually prove.
        const recipientX25519 = fromBase64(recipient.x25519_pub);

        // Recipient copy: CEK wrapped only for them, STORE'd to their relay
        // (onion-routed when requested or required by their record). Bcc is EMPTY on
        // every recipient copy — a Bcc recipient is never revealed, and a reply-all
        // can't leak the Bcc list.
        const forwardTo = recipient.forward_to?.trim();
        let closed = false;
        try {
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
        } catch (e) {
          // The recipient's relay refused the copy because their account is closed. With a
          // forward, that address is where their mail goes now; without one, say so in their
          // name rather than as a delivery error.
          if (!isRecipientClosed(e)) throw e;
          if (!forwardTo) throw new Error(recipientClosedMessage(rcpt), { cause: e });
          closed = true;
        }

        if (forwardTo) {
          const key = forwardTo.toLowerCase();
          if (!reached.has(key)) {
            reached.add(key);
            const { ok, rec: trec } = await sendForwardCopy(forwardTo);
            if (closed && ok) {
              reports.push({
                text: forwardedOnlyMessage(rcpt, forwardTo),
                // Their mail lives there now; a DMCN forwarding address can be saved as a contact.
                ...(trec && !contactByAddress(forwardTo) ? { saveContact: { address: forwardTo, name: contactByAddress(rcpt)?.name ?? '', rec: trec } } : {}),
              });
            } else if (closed) {
              reports.push({ text: forwardOnlyFailedMessage(rcpt, forwardTo) });
            } else if (!ok) {
              reports.push({ text: forwardFailedMessage(rcpt, forwardTo) });
            }
          } else if (closed) {
            // The forwarding address gets this message anyway, as a recipient in its own right.
            reports.push({ text: forwardedOnlyMessage(rcpt, forwardTo) });
          }
        }
      }

      // Sent self-copy: seal the SAME composed message to our OWN X25519 key and store
      // the envelope (a small listed header + a lazy body) in the owner-only personal
      // store. Sent then renders through the normal header/body path — body, attachments,
      // HTML alternatives all live in the body, decrypted on open, exactly like inbox mail
      // — so the Sent list needs only the headers. Sealed to us alone, so it never touches
      // the relay STORE path, onion, or the free-ride guard (the full bcc audience rides on
      // this self-copy only). Best-effort: the message is already delivered, so a Sent-copy
      // failure must not fail the send.
      // Sealed to the ACCOUNT's key whichever identity sent it: Sent is one list, read with
      // one key, and the header still says which address it went out as.
      try {
        const selfEnvelope = await encryptSplit({
          ...common,
          recipientAddress: selfAddress,
          bcc: bccList,
          recipients: [{ deviceId: keys.deviceId, x25519Pub: keys.x25519Public }],
        });
        await new SentStore(keys).putEnvelope(toHex(messageId), selfEnvelope);
      } catch (copyErr) {
        console.warn('Sent copy could not be saved (message delivered):', copyErr);
      }

      // Sent, so no longer a draft. Not awaited: the message is out, and the send is done.
      void removeDraft();
      onSent?.();
      if (reports.length > 0) {
        setSentReport(reports);
        return;
      }
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
    } finally {
      setLoading(false);
    }
  };

  const inputReset = { border: 'none', outline: 'none', background: 'transparent', font: 'inherit' } as const;

  // The forward copies this message will make, and what each one is, for the notice above Send.
  const everyone = [...to, ...cc, ...bcc].map(a => a.trim()).filter(Boolean);
  const forwardCopies = planForwardCopies(
    everyone.map(a => ({ address: a, forwardTo: forwardInfo[a.toLowerCase()]?.target })),
    everyone, from || address || '',
  ).map(c => {
    const info = forwardInfo[c.forAddr.toLowerCase()];
    return { ...c, kind: info?.kind ?? 'unknown' as ForwardTargetKind, unsendable: !!info?.unsendable };
  });
  const forwardLeavesE2E = forwardCopies.some(c => c.kind === 'email');

  const saveForwardContact = async (item: SentReportItem) => {
    const save = item.saveContact;
    if (!save) return;
    const facts = directoryFacts(save.rec);
    await allowlist({
      address: save.address,
      name: save.name,
      fingerprint: save.rec.fingerprint,
      provenance: 'user_approved',
      ed25519Pub: facts.ed25519Pub,
      x25519Pub: facts.x25519Pub,
      adminKeyCustody: facts.adminKeyCustody,
    });
    setSavedContacts(m => ({ ...m, [save.address.toLowerCase()]: true }));
  };

  // Any legacy (non-DMCN) recipient means the message can't be end-to-end encrypted
  // for everyone — surfaced as a warning above the footer.
  const hasLegacy = [...to, ...cc, ...bcc].some(a => recipientInfo[a.trim().toLowerCase()] === 'legacy');
  // Whether any recipient resolved as a DMCN identity — the encryption banner only
  // makes sense (and is only accurate) when there's someone it can be encrypted to.
  const hasDmcn = [...to, ...cc, ...bcc].some(a => recipientInfo[a.trim().toLowerCase()] === 'dmcn');
  // Recipients whose key no longer matches the one we pinned. Nothing is refused over this — the
  // decision belongs to the person who took the pin — so this banner IS the protection rather than
  // an explanation for a refusal, which is why it names every affected address instead of saying
  // "some recipients" and why it sits directly above Send.
  const changedKeyRecipients = [...to, ...cc, ...bcc]
    .map(a => a.trim())
    .filter(a => a && checkPin(contactByAddress(a), recipientKeys[a.toLowerCase()]) === 'changed');
  // Of those, the ones whose identity DISAPPEARED rather than changed keys. A different thing to
  // tell the reader: nothing was swapped, the mail would simply leave the network in the clear.
  const goneRecipients = changedKeyRecipients.filter(a => recipientKeys[a.toLowerCase()]?.noIdentity);
  const keySwapRecipients = changedKeyRecipients.filter(a => !recipientKeys[a.toLowerCase()]?.noIdentity);
  // What the directory can PROVE about each of those changes. It decides nothing — that stays with
  // the person who pinned the key — but "they reported this key stolen" and "their old key
  // approved the change" are different news, and showing the generic sentence for both wastes the
  // one moment a takeover is visible to this user.
  const swapKey = keySwapRecipients.join(',').toLowerCase();
  useEffect(() => {
    let live = true;
    for (const addr of keySwapRecipients) {
      const key = addr.toLowerCase();
      if (keyChanges[key]) continue;
      const pinned = contactFacts(contactByAddress(addr))?.ed25519Pub;
      if (!pinned) continue;
      void loadKeyChange(addr, pinned).then(change => {
        if (live) setKeyChanges(m => (m[key] ? m : { ...m, [key]: change }));
      });
    }
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed on WHICH recipients changed; the map itself is written here and would loop
  }, [swapKey]);

  // confirmChange records the state the directory is showing NOW as the verified one, which is
  // what clears the warning for this recipient — until it changes again. It re-pins rather than
  // clearing: the point of confirming is to move the pin forward, not to stop watching.
  // The evidence sentence for one recipient, or the generic one while it is still loading. A
  // missing explanation reads as "nothing signed explains this", which is the honest default: it
  // is also exactly what a withheld record looks like.
  const changeFor = (addr: string) => keyChanges[addr.toLowerCase()];

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
            adminKeyCustody: observed.adminKeyCustody,
          }),
    });
  };
  // Recipients whose KEYS still match but whose pinned properties moved. A quieter warning than
  // the one above, because no message is mis-sealed by it. Still shown, because
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
    // Every input event inside the composer is an edit: the fields, the rich body (typing, pasting,
    // the toolbar), the From choice, the file picker. Clicks that change the message call markEdited
    // themselves.
    <div style={shell} onInputCapture={markEdited}>
      {/* Title bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: 'var(--space-3) var(--space-4)', background: 'var(--neutral-900)', color: 'var(--neutral-25)' }}>
        <span style={{ fontSize: 'var(--text-md)', fontWeight: 600 }}>{replyTo ? 'Reply' : 'New message'}</span>
        <button aria-label="Close" onClick={() => { void putAway(); }} style={{ border: 'none', background: 'transparent', color: 'inherit', cursor: 'pointer', display: 'flex' }}>
          <Icon name="x" size={18} />
        </button>
      </div>

      {/* From: only when there is a choice to make. */}
      {senders.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderBottom: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)' }}>
          <span style={{ color: 'var(--text-muted)', minWidth: 32 }}>From</span>
          <select
            aria-label="From"
            value={from}
            onChange={e => setFrom(e.target.value)}
            style={{ flex: 1, minWidth: 0, background: 'transparent', color: 'var(--text-body)', border: 'none', fontSize: 'inherit', fontFamily: 'inherit', cursor: 'pointer' }}
          >
            <option value={address ?? ''}>{address}</option>
            {senders.map(a => <option key={a.address} value={a.address}>{a.address}</option>)}
          </select>
        </div>
      )}

      {/* Recipients */}
      <RecipientField
        label="To"
        values={to}
        onRemove={r => { markEdited(); setTo(to.filter(x => x !== r)); }}
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
            onRemove={r => { markEdited(); setCc(cc.filter(x => x !== r)); }}
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
            onRemove={r => { markEdited(); setBcc(bcc.filter(x => x !== r)); }}
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

      {/* After sending, what the sender should know about where it went. Replaces the send
          controls below, so the same message cannot be sent twice from here. */}
      {sentReport && (
        <div role="status" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: 'var(--space-3) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--brand-subtle)', color: 'var(--text-body)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontWeight: 600 }}>
            <Icon name="check" size={15} style={{ color: 'var(--brand)' }} />
            Sent.
          </div>
          {sentReport.map(item => (
            <div key={item.text} style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', paddingLeft: 23 }}>
              <span>{item.text}</span>
              {item.saveContact && (savedContacts[item.saveContact.address.toLowerCase()]
                ? <span style={{ color: 'var(--text-muted)' }}>Added to your contacts.</span>
                : (
                  <Button size="sm" variant="secondary" onClick={() => { void saveForwardContact(item); }}>
                    Add {item.saveContact.address} to contacts
                  </Button>
                ))}
            </div>
          ))}
        </div>
      )}

      {/* Changed-key warning. Ranked ABOVE the legacy and encryption banners because it is the
          most serious thing on the screen, and because "end-to-end encrypted" sitting alone under
          a swapped key would be technically true and dangerously misleading. */}
      {changedKeyRecipients.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--danger-subtle)', color: 'var(--text-body)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--danger)', flex: 'none', marginTop: 2 }} />
            <span>
              {keySwapRecipients.map(a => (
                <span key={a}>{pinnedKeyWarning(a, changeFor(a))}{' '}</span>
              ))}
              {goneRecipients.map(a => (
                <span key={a}>{pinnedIdentityGoneWarning(a)}{' '}</span>
              ))}
              {/* The sentences above carry the risk and the safe order. This adds the two things
                  they cannot know: that nothing here stops the send, and what pressing Confirm
                  does. Saying "you can still send" out loud matters — a warning that reads like a
                  refusal gets treated as an obstacle to get past, and then it stops being read. */}
              You can still send. Confirm once you have checked with them, and the warning clears
              until something changes again.
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

      {/* Forwarding: a recipient's mail also goes to an address they chose. Said before Send, in
          their name and the address's, and whether that copy stays end-to-end encrypted. Never
          blocks the send: forwarding is the recipient's arrangement, not a risk to confirm. */}
      {forwardCopies.length > 0 && !sentReport && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: forwardLeavesE2E ? 'var(--warning-subtle)' : 'var(--brand-subtle)', color: 'var(--text-body)' }}>
          <Icon name={forwardLeavesE2E ? 'alert-triangle' : 'shield-check'} size={15} style={{ color: forwardLeavesE2E ? 'var(--warning)' : 'var(--brand)', flex: 'none', marginTop: 2 }} />
          <span>
            {forwardCopies.map(c => (
              <span key={c.target}>
                {c.unsendable
                  ? forwardUnsendableNotice(c.forAddr, c.target)
                  : forwardNotice(c.forAddr, c.target, c.kind)}{' '}
              </span>
            ))}
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

      {/* Two copies of this draft: the person decides which one stays. Saving waits until they do. */}
      {(saveState === 'conflict' || saveState === 'gone') && !sentReport && (
        <div role="alert" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-4)', borderTop: '1px solid var(--border-subtle)', fontSize: 'var(--text-sm)', background: 'var(--warning-subtle)', color: 'var(--text-body)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)' }}>
            <Icon name="alert-triangle" size={15} style={{ color: 'var(--warning)', flex: 'none', marginTop: 2 }} />
            <span>
              {saveState === 'gone'
                ? 'This draft was sent or deleted on another device. Your changes here are not saved yet.'
                : 'This draft was changed on another device. Your changes here are not saved yet.'}
            </span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', paddingLeft: 23 }}>
            <Button size="sm" variant="secondary" onClick={() => { void keepThisCopy(); }}>
              {saveState === 'gone' ? 'Keep it as a draft' : 'Keep this version'}
            </Button>
            {saveState === 'conflict' && onReopenDraft && (
              <Button size="sm" variant="secondary" onClick={() => { void openOtherCopy(); }}>Open the other version</Button>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      {sentReport ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-3) var(--space-4)', borderTop: '1px solid var(--border-subtle)' }}>
          <Button onClick={onClose}>Done</Button>
        </div>
      ) : (
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
        {saveLabel && (
          <span aria-live="polite" style={{ fontSize: 'var(--text-xs)', color: saveState === 'failed' || saveState === 'full' ? 'var(--danger)' : 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            {saveLabel}
          </span>
        )}
        <ConfirmTrashButton aria-label="Discard" onConfirm={handleDiscard} />
      </div>
      )}
    </div>
  );
}

const fieldInputReset = { border: 'none', outline: 'none', background: 'transparent', font: 'inherit' } as const;

// One line of the after-send report, optionally offering to save a recipient's new DMCN address.
interface SentReportItem {
  text: string;
  saveContact?: { address: string; name: string; rec: IdentityLookupResponse };
}

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
        const kind: RecipientKind | undefined = info === 'legacy' || info === 'unchecked' ? info : isContact ? 'trusted' : info;
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
