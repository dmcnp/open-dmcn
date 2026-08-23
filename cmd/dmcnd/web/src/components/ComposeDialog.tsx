import { useState, useRef, useEffect } from 'react';
import type { CSSProperties, ReactNode, KeyboardEvent } from 'react';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { lookupIdentity, sendMessage } from '../lib/api/client';
import { encryptSplit, type SplitEnvelope } from '../lib/crypto/split';
import { encodeSplitEnvelope } from '../lib/crypto/protobuf';
import { signWithKey } from '../lib/crypto/sign';
import { toBase64, fromBase64, toHex } from '../lib/crypto/keys';
import { SentStore, sentAuthorBytes, type SentEntry } from '../lib/api/sentStore';
import { useSettings } from '../lib/hooks/useSettings';
import { useContacts, type Contact } from '../lib/hooks/useContacts';
import { DEFAULT_DOMAIN } from '../lib/config';
import { Button, IconButton, Tag, Avatar } from '../ds';
import { Icon } from './Icon';

export interface ComposeReplyTo {
  to: string;
  subject: string;
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
  const { contacts } = useContacts();

  // Three recipient classes with standard email semantics. To/Cc are visible to
  // everyone; Bcc is only recorded on the sender's own Sent copy (see handleSend).
  const [to, setTo] = useState<string[]>(replyTo?.to ? [replyTo.to] : []);
  const [cc, setCc] = useState<string[]>([]);
  const [bcc, setBcc] = useState<string[]>([]);
  const [pendingTo, setPendingTo] = useState('');
  const [pendingCc, setPendingCc] = useState('');
  const [pendingBcc, setPendingBcc] = useState('');
  const [showCcBcc, setShowCcBcc] = useState(false);
  const [subject, setSubject] = useState(replyTo?.subject ? `Re: ${replyTo.subject.replace(/^Re:\s*/i, '')}` : '');
  const [body, setBody] = useState('');
  // Onion routing is no longer user-selectable (not enough peers yet), but if a
  // recipient's record or domain REQUIRES onion delivery the server enforces it, so
  // we still detect it and route accordingly.
  const [onion, setOnion] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const recipientInput = useRef<HTMLInputElement>(null);
  // Per-recipient classification (keyed by lowercased address) for the chip shields.
  const [recipientInfo, setRecipientInfo] = useState<Record<string, RecipientKind>>({});

  // inspectRecipient resolves a recipient once: records whether it's a DMCN identity
  // or a legacy (non-DMCN) address, and turns on onion delivery when the record or its
  // domain requires it. The trusted-contact (blue) upgrade is applied at render time
  // from the contact list, so it appears the moment contacts load regardless of order.
  const inspectRecipient = async (addr: string) => {
    const key = addr.trim().toLowerCase();
    try {
      const rec = await lookupIdentity(addr);
      if (rec.require_onion) setOnion(true);
      // A legacy lookup succeeds, but what it resolves is the BRIDGE, not a correspondent: the
      // message is sealed to the bridge and leaves the network as ordinary email. Say so, rather
      // than showing it as a DMCN identity because a lookup happened to return 200.
      setRecipientInfo(m => ({ ...m, [key]: rec.legacy ? 'legacy' : 'dmcn' }));
    } catch {
      // Unresolvable in either direction — not a DMCN identity, and no bridge to carry it.
      // handleSend surfaces the send error.
      setRecipientInfo(m => ({ ...m, [key]: 'legacy' }));
    }
  };

  // Pre-filled (reply) recipients may already require onion.
  useEffect(() => {
    to.forEach(r => void inspectRecipient(r));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Prefill the composing signature (synced setting) for a NEW message, once the
  // setting loads — but never clobber a reply or text the user already typed.
  const sigApplied = useRef(false);
  useEffect(() => {
    if (sigApplied.current) return;
    if (replyTo) { sigApplied.current = true; return; }
    if (settings.signature) {
      setBody(b => (b === '' ? '\n\n' + settings.signature : b));
      sigApplied.current = true;
    }
  }, [settings.signature, replyTo]);

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
      const envHash = new Uint8Array(await crypto.subtle.digest('SHA-256', envBytes));
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
    const threadId = crypto.getRandomValues(new Uint8Array(16));
    threadId[6] = (threadId[6] & 0x0f) | 0x40;
    threadId[8] = (threadId[8] & 0x3f) | 0x80;
    const sentAt = Math.floor(Date.now() / 1000);

    // Shared header fields. recipientAddress (per-copy routing label) and bcc are
    // filled in per copy below; to/cc are identical and visible everywhere.
    const common = {
      version: 1,
      messageId,
      threadId,
      senderAddress: selfAddress,
      senderPublicKey: k.ed25519Public,
      senderSignKey: k.ed25519Sign,
      sentAt,
      subject,
      bodyText: body,
      to: toList,
      cc: ccList,
    };

    setLoading(true);
    setError('');
    try {
      // Deliver a copy to each recipient, recording the relay-accept hash per address.
      const acceptHashes: Record<string, string> = {};
      for (const rcpt of allRecipients) {
        const recipient = await lookupIdentity(rcpt);
        const recipientX25519 = fromBase64(recipient.x25519_pub);

        // Recipient copy: CEK wrapped only for them, STORE'd to their relay
        // (onion-routed when requested or required by their record). Bcc is EMPTY on
        // every recipient copy — a Bcc recipient is never revealed, and a reply-all
        // can't leak the Bcc list.
        acceptHashes[rcpt] = await storeEnvelope(
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

      // Sent copy: a record in the owner-only personal store ("sent/" namespace), NOT
      // a message. Sealed to us alone, so it never touches onion routing, the relay
      // STORE path, or the free-ride guard — this is what retires the old
      // self-addressed STORE (and fixes the RequireOnion-on-self failure). It records
      // the full to/cc/bcc audience, the authorship signature, and each recipient's
      // relay-accept hash. Best-effort: the message is already delivered, so a failure
      // to save our own Sent copy must not fail the send.
      const sentEntry: SentEntry = {
        v: 1,
        messageId: toHex(messageId),
        threadId: toHex(threadId),
        sentAt,
        subject,
        body,
        to: toList,
        cc: ccList,
        bcc: bccList,
        attachments: [],
        authorSig: '',
        acceptHashes,
      };
      sentEntry.authorSig = toBase64(await signWithKey(k.ed25519Sign, sentAuthorBytes(sentEntry)));
      try {
        await new SentStore(k).put(sentEntry);
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

      {/* Body */}
      <textarea
        value={body}
        onChange={e => setBody(e.target.value)}
        placeholder="Write something — it's encrypted before it leaves your device."
        style={{ ...inputReset, resize: 'none', fontSize: mobile ? 16 : 'var(--text-base)', lineHeight: 'var(--leading-relaxed)', color: 'var(--text-body)', padding: 'var(--space-4)', minHeight: mobile ? 0 : 200, flex: 1 }}
      />

      {error && (
        <div style={{ padding: 'var(--space-2) var(--space-4)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>{error}</div>
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
}

const MAX_SUGGESTIONS = 6;

/** A chip-list recipient input row (To / Cc / Bcc share this), with contact type-ahead. */
function RecipientField({ label, values, onRemove, pending, setPending, onKey, onBlur, placeholder, mobile, inputRef, rightSlot, contacts, onPick, recipientInfo }: RecipientFieldProps) {
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
            {r}
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
              <Avatar name={c.name || c.address} size="sm" />
              <div style={{ minWidth: 0, flex: 1 }}>
                {c.name && (
                  <div style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.name}</div>
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
