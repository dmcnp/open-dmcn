import { useEffect, useRef, useState } from 'react';
import { useMessages } from '../lib/hooks/useMessages';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { sendMessage } from '../lib/api/client';
import { deviceSendProof } from '../lib/crypto/deviceKey';
import { Badge, Button } from '../ds';
import { Icon } from './Icon';
import {
  confirmationCode,
  splitConfirmationCode,
  extractCloneRequest,
  cloneResponseAttachment,
  SUBJECT_REQUEST,
  SUBJECT_APPROVAL,
} from '../lib/crypto/pairing';
import { enrolDevice, sealDeviceLabel, signerFor } from '../lib/api/deviceRegistry';
import { encryptSplit } from '../lib/crypto/split';
import { encodeSplitEnvelope } from '../lib/crypto/protobuf';
import { signWithKey } from '../lib/crypto/sign';
import { toBase64 } from '../lib/crypto/keys';
import { unlockBackupBytes, localAuthMethod } from '../lib/crypto/reauth';
import { Input } from '../ds';
import { bufferSource } from '../lib/crypto/bytes';

interface PendingReq {
  hash: string;
  ephAddr: string;
  label: string;
  code: string;
  ephX: Uint8Array;
  /** The new device's own signing key, to enrol it on the mailbox. Empty from an older client. */
  devicePub: Uint8Array;
}

const codeTextStyle = {
  fontSize: 'var(--text-xl)',
  fontWeight: 700,
  letterSpacing: 2,
  fontFamily: 'var(--font-mono)',
  color: 'var(--text-strong)',
} as const;

// The digit field carries the design system's own input chrome (.dmcn-input: border,
// focus ring, invalid state) and overrides only what makes it read as the code's
// missing last group — mono, the same size as the digits beside it, four wide.
// Wider than the four digits measure: at 6ch the field cropped its own first digit,
// since 'ch' is the mono zero's advance and the box has to hold the letter-spacing,
// the padding and the border too.
const codeInputStyle = {
  ...codeTextStyle,
  boxSizing: 'border-box',
  width: '8ch',
  padding: '0 var(--space-2)',
  textAlign: 'center',
} as const;

function uuid(): Uint8Array {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return b;
}

// The device-pairing queue, shown by the inbox notice of the same subject (see deployment.tsx).
export function DeviceRequests({ onClose }: { onClose: () => void }) {
  const { messages, openMessageFull, deleteMessage } = useMessages();
  const { address } = useAuth();
  const { keys } = useKeys();

  const [requests, setRequests] = useState<PendingReq[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState('');
  // When the local keystore is password-gated, approving requires re-entering the
  // password to unlock the raw key bytes that get sealed to the new device. pwFor
  // holds the request awaiting that password.
  const [pwFor, setPwFor] = useState<PendingReq | null>(null);
  const [pw, setPw] = useState('');
  // The last group of each request's confirmation code, as typed here. It is never
  // shown on this device, so filling it in is proof the person read it off the new
  // device's screen rather than waving the request through. Keyed by request hash.
  const [typed, setTyped] = useState<Record<string, string>>({});
  const loadedRef = useRef<Set<string>>(new Set());

  const codeConfirmed = (req: PendingReq) => typed[req.hash] === splitConfirmationCode(req.code).typed;

  // Scan inbox previews for pairing-request control messages and decode each
  // one's attachment to recover the ephemeral key + confirmation code.
  useEffect(() => {
    if (!address) return;
    const pendingHashes = new Set(messages.filter(m => m.subject === SUBJECT_REQUEST).map(m => m.hash));
    // Drop requests that no longer exist in the mailbox.
    setRequests(prev => prev.filter(r => pendingHashes.has(r.hash)));
    setTyped(prev => {
      const stale = Object.keys(prev).filter(h => !pendingHashes.has(h));
      if (!stale.length) return prev;
      const next = { ...prev };
      for (const h of stale) delete next[h];
      return next;
    });
    for (const m of messages) {
      if (m.subject !== SUBJECT_REQUEST || loadedRef.current.has(m.hash)) continue;
      loadedRef.current.add(m.hash);
      void (async () => {
        try {
          const full = await openMessageFull(m.hash);
          const req = await extractCloneRequest(full.attachments);
          if (!req) return;
          const code = await confirmationCode(address, req.ephemeralEd25519Pub, req.ephemeralX25519Pub);
          setRequests(prev =>
            prev.some(r => r.hash === m.hash)
              ? prev
              : [...prev, {
                hash: m.hash, ephAddr: m.senderAddress, label: req.label, code,
                ephX: req.ephemeralX25519Pub,
                devicePub: req.deviceEd25519Pub ?? new Uint8Array(0),
              }]
          );
        } catch {
          loadedRef.current.delete(m.hash); // allow a retry on the next sync
        }
      })();
    }
  }, [messages, address, openMessageFull]);

  // approve gates on the local unlock method: passkey unlocks inline (WebAuthn
  // prompt is the gesture), password reveals a field and defers to doApprove.
  const approve = async (req: PendingReq) => {
    if (!address) return;
    if (!codeConfirmed(req)) { setError('Enter the last four digits shown on the new device.'); return; }
    setError('');
    const method = await localAuthMethod(address);
    if (method === 'password') {
      setPw('');
      setPwFor(req);
      return;
    }
    await doApprove(req);
  };

  // doApprove seals the account key bundle to the requester's ephemeral key and
  // sends it. The raw bytes come transiently from the local keystore (reauth) — the
  // non-extractable working handles can't yield them — and are discarded after use.
  // The envelope itself is signed with the working handle, no raw key needed.
  const doApprove = async (req: PendingReq, password?: string) => {
    if (!keys || !address) return;
    if (!codeConfirmed(req)) { setError('Enter the last four digits shown on the new device.'); return; }
    setBusy(req.hash);
    setError('');
    try {
      const { kp: rawKp } = await unlockBackupBytes(address, password ? { password } : undefined);
      const now = Math.floor(Date.now() / 1000);

      // Enrol the newcomer BEFORE handing over the account keys, so it can open the mailbox the
      // moment it has them. The order matters the other way round too: if the enrolment fails we
      // stop here rather than sending a key bundle to a device the relay will not admit.
      //
      // The approving device does this rather than the newcomer, and must: an approval is signed
      // over a live challenge nonce, and only a party already authenticated on the mailbox can
      // obtain one. A newcomer holding a signed blob to spend later is what that binding exists
      // to rule out.
      if (req.devicePub.length > 0) {
        // The name the new device gave itself goes on its entry, sealed to this account, so the
        // device list in Privacy & security can say which one it is.
        const label = await sealDeviceLabel(req.label, keys.x25519Public);
        await enrolDevice(address, signerFor(keys), req.devicePub, now, label);
      }
      const att = await cloneResponseAttachment(rawKp, address);
      const envelope = await encryptSplit({
        version: 1,
        messageId: uuid(),
        threadId: uuid(),
        senderAddress: address,
        senderPublicKey: keys.ed25519Public,
        senderSignKey: keys.ed25519Sign,
        recipientAddress: req.ephAddr,
        sentAt: now,
        subject: SUBJECT_APPROVAL,
        bodyText: 'Device pairing approved.',
        attachments: [att],
        recipients: [{ deviceId: new Uint8Array(16), x25519Pub: req.ephX }],
      });
      const envBytes = await encodeSplitEnvelope(envelope);
      const envHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(envBytes)));
      const envSignature = await signWithKey(keys.ed25519Sign, envHash);
      await sendMessage({
        sender_address: address,
        sender_signature: toBase64(envSignature),
        envelope: toBase64(envBytes),
        recipient_address: req.ephAddr,
        // This device is enrolled (it just approved the newcomer), and the account's home relay
        // admits a send only from an enrolled device.
        ...(await deviceSendProof(address, envHash)),
      });
      // Remove the consumed request from our mailbox.
      try { await deleteMessage(req.hash); } catch { /* ignore */ }
      setRequests(prev => prev.filter(r => r.hash !== req.hash));
      setTyped(prev => { const next = { ...prev }; delete next[req.hash]; return next; });
      setPwFor(null);
      setPw('');
      setDone(req.code);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'failed to approve');
    } finally {
      setBusy(null);
    }
  };

  const dismiss = async (req: PendingReq) => {
    setBusy(req.hash);
    try { await deleteMessage(req.hash); } catch { /* ignore */ }
    setRequests(prev => prev.filter(r => r.hash !== req.hash));
    setTyped(prev => { const next = { ...prev }; delete next[req.hash]; return next; });
    setBusy(null);
  };

  return (
    <>
      <p style={{ margin: '0 0 var(--space-4)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', lineHeight: 'var(--leading-normal)' }}>
        Read the code off the new device and type its last four digits here. They have to match before
        the request can be approved — approving sends your keys to that device, end-to-end encrypted.
      </p>

      {done && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
          <Icon name="shield-check" size={16} style={{ color: 'var(--brand)' }} />
          Approved device with code {done}.
        </div>
      )}
      {error && (
        <div style={{ marginBottom: 'var(--space-4)', padding: 'var(--space-3)', background: 'var(--danger-subtle)', color: 'var(--danger)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>{error}</div>
      )}

      {pwFor && (
        <form
          onSubmit={e => { e.preventDefault(); void doApprove(pwFor, pw); }}
          style={{ marginBottom: 'var(--space-4)', padding: 'var(--space-4)', background: 'var(--surface-inset)', border: '1px solid var(--border-default)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}
        >
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            Enter your password to approve <strong>{pwFor.label || 'this device'}</strong> (code {pwFor.code}).
            Your keys are unlocked only to seal them to the new device.
          </div>
          <Input label="Password" type="password" value={pw} onChange={e => setPw(e.target.value)} autoFocus />
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <Button size="sm" type="submit" disabled={busy === pwFor.hash || !pw}>
              {busy === pwFor.hash ? 'Approving…' : 'Confirm approval'}
            </Button>
            <Button size="sm" variant="secondary" type="button" disabled={busy === pwFor.hash} onClick={() => { setPwFor(null); setPw(''); }}>Cancel</Button>
          </div>
        </form>
      )}

      {requests.length === 0 ? (
        <div style={{ padding: 'var(--space-8) var(--space-4)', textAlign: 'center', color: 'var(--text-muted)' }}>
          <Icon name="monitor" size={28} style={{ color: 'var(--text-subtle)', margin: '0 auto' }} />
          <p style={{ margin: 'var(--space-3) 0 var(--space-4)', fontSize: 'var(--text-base)' }}>No pending device requests.</p>
          <Button size="sm" variant="secondary" onClick={onClose}>Close</Button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
          {requests.map(req => (
            <div key={req.hash} style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-4)', padding: 'var(--space-4)', background: 'var(--surface-inset)', border: '1px solid var(--border-default)' }}>
              <div style={{ width: 40, height: 40, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border-default)', color: 'var(--text-muted)' }}>
                <Icon name="monitor" size={20} />
              </div>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <span style={{ fontSize: 'var(--text-md)', fontWeight: 600, color: 'var(--text-strong)' }}>{req.label || 'New device'}</span>
                  <Badge variant="warning" dot>Awaiting approval</Badge>
                </div>
                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginTop: 2, overflowWrap: 'anywhere' }}>{req.ephAddr}</div>
                <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 6, marginTop: 'var(--space-2)' }}>
                  <span style={codeTextStyle}>{splitConfirmationCode(req.code).shown}</span>
                  <span style={{ ...codeTextStyle, color: 'var(--text-subtle)' }}>-</span>
                  <input
                    value={typed[req.hash] ?? ''}
                    onChange={e => {
                      const v = e.target.value.replace(/\D/g, '').slice(0, 4);
                      setTyped(prev => ({ ...prev, [req.hash]: v }));
                    }}
                    inputMode="numeric"
                    autoComplete="off"
                    maxLength={4}
                    placeholder="0000"
                    aria-label={`Last four digits of the code shown on ${req.label || 'the new device'}`}
                    aria-invalid={(typed[req.hash] ?? '').length === 4 && !codeConfirmed(req)}
                    className={'dmcn-input' + ((typed[req.hash] ?? '').length === 4 && !codeConfirmed(req) ? ' dmcn-input--invalid' : '')}
                    style={codeInputStyle}
                  />
                </div>
                <div style={{ fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)', color: codeConfirmed(req) ? 'var(--success)' : (typed[req.hash] ?? '').length === 4 ? 'var(--danger)' : 'var(--text-muted)' }}>
                  {codeConfirmed(req)
                    ? 'Code matches.'
                    : (typed[req.hash] ?? '').length === 4
                      ? "That's not the code on the new device."
                      : 'Type the last four digits shown on the new device.'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-2)', flex: 'none' }}>
                <Button size="sm" disabled={busy === req.hash || !codeConfirmed(req)} onClick={() => approve(req)}>
                  {busy === req.hash ? 'Approving…' : 'Approve'}
                </Button>
                <Button variant="secondary" size="sm" disabled={busy === req.hash} onClick={() => dismiss(req)}>Dismiss</Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
