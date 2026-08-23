import { useEffect, useState } from 'react';
import type { CSSProperties } from 'react';
import type { Preview } from '../lib/api/mailboxRest';
import { useMessages } from '../lib/hooks/useMessages';
import { useFlags } from '../lib/hooks/useFlags';
import { useLabels } from '../lib/hooks/useLabels';
import type { LabelDef } from '../lib/api/labelStore';
import { useAuth } from '../lib/hooks/useAuth';
import { Avatar, Badge, Button, IconButton, Tag } from '../ds';
import { Icon } from './Icon';
import { lookupIdentity } from '../lib/api/client';
import { verifyBridgeAttestation, BridgeTrustTier, type BridgeAttestation } from '../lib/crypto/bridgeAttest';
import { evaluateSenderTrust, type SenderTrust } from '../lib/crypto/senderTrust';
import { senderTrustView } from '../lib/trust/trustView';
import { useContacts } from '../lib/hooks/useContacts';
import { useMailFilter } from '../lib/hooks/useMailFilter';
import { categorizeSender } from '../lib/trust/category';
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

export interface MessageReaderProps {
  msg: Preview;
  sentView: boolean;
  onBack: () => void;
  onReply: (msg: Preview) => void;
  /** Tighter padding + smaller title on mobile. */
  mobile?: boolean;
  /** When set, render this body inline instead of fetching from the mailbox — used
   *  for Sent entries read from the personal store, which carry their own body. */
  inlineBody?: string | null;
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
export function MessageReader({ msg, sentView, onBack, onReply, mobile = false, inlineBody, onDeleteOverride, starred, archived, onToggleStar, onArchive }: MessageReaderProps) {
  const { openMessageFull, deleteMessage } = useMessages();
  const { labelsOf, folderOf, addLabel, removeLabel, setFolder, removeFlags } = useFlags();
  const { labels, folders, labelById } = useLabels();
  const { address } = useAuth();
  const { contactByAddress, allowlist, pinKey, ready: contactsReady } = useContacts();
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

  const inline = inlineBody !== undefined && inlineBody !== null;
  const [body, setBody] = useState<string | null>(inline ? inlineBody : null);
  const [bodyError, setBodyError] = useState<string | null>(null);
  const [attestation, setAttestation] = useState<BridgeAttestation | null>(null);
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

  // Sent records from the personal store carry their own body (no mailbox fetch, no
  // bridge attestation). Otherwise fetch + verify the body on open (the inbox only
  // holds previews); for bridged legacy mail, verify the bridge's signed
  // classification attestation client-side before trusting the tier it claims.
  useEffect(() => {
    if (inline) {
      setBody(inlineBody);
      setBodyError(null);
      setAttestation(null);
      return;
    }
    let cancelled = false;
    setBody(null);
    setBodyError(null);
    setAttestation(null);
    openMessageFull(msg.hash)
      .then(full => {
        if (cancelled) return;
        setBody(full.bodyText);
        verifyBridgeAttestation(full.attachments)
          .then(a => { if (!cancelled) setAttestation(a); })
          .catch(() => { /* unexpected: treat as non-bridged, show no badge */ });
      })
      .catch(err => { if (!cancelled) setBodyError(err instanceof Error ? err.message : 'Failed to load message body'); });
    return () => { cancelled = true; };
  }, [msg.hash, openMessageFull, inline, inlineBody]);

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
  // Native trust badge/callout — suppressed when a bridge attestation is shown
  // (bridged legacy mail: the DMCN "sender" is the bridge, not the real author), and
  // held back until the allowlist + filter are loaded so it resolves straight to the
  // correct verdict instead of flashing "unknown" first.
  const tv = contactsReady && filterReady && !av && nativeTrust ? senderTrustView(nativeTrust) : null;

  // Pending-queue category (§14.2). Your own Sent copies are never gated. Blocked/
  // pending senders' bodies stay behind the gate until trusted or revealed. trustReady
  // guards a cold load: don't gate (or show the body) until contacts + filter are
  // loaded, so we never flash the wrong state.
  const trustReady = ownMessage || (contactsReady && filterReady);
  const category = ownMessage ? 'allowlisted' : categorizeSender(msg.senderAddress, msg.senderPublicKey, senderContact, mailFilter);
  const gated = trustReady && category !== 'allowlisted';

  // Reset per-message UI (accept-once reveal + prior trust verdict) when the open
  // message changes, so nothing from the previous message lingers.
  useEffect(() => { setRevealed(false); setNativeTrust(null); }, [msg.hash]);

  // Lazy key-pin (§14.1.2): once a message from an allowlisted-but-unpinned contact
  // verifies as allowlisted (header key == directory key), record the keys so a
  // later unsigned change is detectable. Runs at most once per unpinned contact.
  useEffect(() => {
    if (ownMessage || nativeTrust?.kind !== 'allowlisted' || !senderContact || senderContact.ed25519Pub) return;
    let cancelled = false;
    lookupIdentity(msg.senderAddress)
      .then(dir => { if (!cancelled) return pinKey(msg.senderAddress, dir.ed25519_pub, dir.x25519_pub); })
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
        // Pin the DIRECTORY key: if it disagrees with the header key (impersonation),
        // the sender stays pending rather than being trusted into the inbox.
        ed25519Pub: dir.ed25519_pub,
        x25519Pub: dir.x25519_pub,
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
            {tv && <Badge variant={tv.variant} icon={<Icon name={tv.icon} size={12} />}>{tv.label}</Badge>}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', marginTop: 'var(--space-5)' }}>
            <Avatar name={counterparty} size="md" />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {sentView ? <>To <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>{toList.join(', ')}</span></> : counterparty}
              </div>
              {!sentView && toList.length > 0 && (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  To {toList.join(', ')}
                </div>
              )}
              {msg.cc.length > 0 && (
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Cc {msg.cc.join(', ')}
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
            <IconButton aria-label="Reply" onClick={() => onReply(msg)}><Icon name="reply" /></IconButton>
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
            </>
          )}

          <div style={{ marginTop: 'var(--space-6)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
            <Icon name="shield-check" size={16} />
            End-to-end encrypted over dmcn — only you and {counterparty} can read this.
          </div>

          {av && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${av.variant}-subtle)`, color: `var(--${av.variant === 'success' ? 'success' : av.variant === 'warning' ? 'warning' : 'danger'})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={av.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>{av.detail}</span>
            </div>
          )}

          {tv && (
            <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: `var(--${tv.variant}-subtle)`, color: `var(--${tv.variant})`, fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
              <Icon name={tv.icon} size={16} style={{ marginTop: 1, flex: 'none' }} />
              <span>{tv.detail}</span>
            </div>
          )}

          <div style={{ marginTop: 'var(--space-6)', display: 'flex', gap: 'var(--space-2)' }}>
            <Button variant="secondary" leftIcon={<Icon name="reply" size={16} />} onClick={() => onReply(msg)}>Reply</Button>
          </div>
        </div>
      </div>
    </div>
  );
}
