import { useEffect, useRef, useState } from 'react';
import { commitPairingDeviceKey, pairingDeviceKey } from '../lib/crypto/deviceKey';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { getRelayHints, lookupIdentity, sendMessage, importChallenge, importIdentity, setSessionToken } from '../lib/api/client';
import { pairSession, pairRegister } from '../lib/api/client';
import { MailboxSync, type Preview } from '../lib/api/mailboxRest';
import { generateIdentityKeyPair, toBase64, fromBase64, type IdentityKeyPair } from '../lib/crypto/keys';
import { importWorkingKeys } from '../lib/crypto/workingKeys';
import { makeLocalKeystore, saveLocalKeystore } from '../lib/crypto/localKeystore';
import {
  ephemeralAddress,
  buildEphemeralRecord,
  confirmationCode,
  splitConfirmationCode,
  cloneRequestAttachment,
  extractCloneResponse,
  SUBJECT_REQUEST,
  SUBJECT_APPROVAL,
} from '../lib/crypto/pairing';
import { keyPairToPayloadJSON } from '../lib/crypto/keys';
import { encryptSplit } from '../lib/crypto/split';
import { encodeSplitEnvelope } from '../lib/crypto/protobuf';
import { sign, signWithKey } from '../lib/crypto/sign';
import { encryptKeys, encryptKeysWithKey } from '../lib/crypto/keystore';
import { isPasskeySupported, createPasskeyPRF } from '../lib/crypto/passkey';
import { AuthShell } from '../components/AuthShell';
import { ChoiceCard } from '../components/ChoiceCard';
import { DOMAINS } from '../lib/config';
import { EmailAddressField } from '../components/EmailAddressField';
import { Button, Input } from '../ds';
import { Icon } from '../components/Icon';
import { bufferSource } from '../lib/crypto/bytes';

const linkStyle = { color: 'var(--text-link)', textDecoration: 'none', fontWeight: 600 } as const;
const fieldLabelStyle = { fontSize: 'var(--text-sm)', fontWeight: 'var(--weight-medium)', color: 'var(--text-body)', display: 'block', marginBottom: 'var(--space-2)' } as const;

function uuid(): Uint8Array {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  return b;
}

type Choice = 'passkey' | 'password' | 'single';

export function PairDevice() {
  // The account address to pair to is a local-part + a domain chosen from the deploy's
  // served domains (env.DOMAINS), composed into `local@domain`.
  //
  // A browser sent here to pair again (UnapprovedDeviceNotice) arrives with ?address= so the
  // account it already knows is filled in; its domain joins the choices if the deploy does not
  // list it, as a customer's own domain would not be.
  const [prefill] = useState(() => {
    const addr = new URLSearchParams(window.location.search).get('address') ?? '';
    const at = addr.lastIndexOf('@');
    return at > 0 ? { local: addr.slice(0, at), domain: addr.slice(at + 1).toLowerCase() } : null;
  });
  const domains = prefill && !DOMAINS.includes(prefill.domain) ? [...DOMAINS, prefill.domain] : DOMAINS;
  const [localPart, setLocalPart] = useState(prefill?.local ?? '');
  const [domain, setDomain] = useState(prefill?.domain ?? DOMAINS[0] ?? '');
  const account = localPart.trim() ? `${localPart.trim()}@${domain}` : '';
  const [label, setLabel] = useState('');
  const passkeyOk = isPasskeySupported();
  const [choice, setChoice] = useState<Choice>(passkeyOk ? 'passkey' : 'password');
  const [password, setPassword] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [step, setStep] = useState<'form' | 'verify'>('form');
  const [code, setCode] = useState('');
  const [approved, setApproved] = useState(false);
  const [finalizing, setFinalizing] = useState(false);
  // Passkey enrollment failed after approval — offer the password path rather than
  // making the user redo the pairing (see the catch in finalize).
  const [passkeyFailed, setPasskeyFailed] = useState(false);
  const [error, setError] = useState('');

  const { setSession } = useAuth();
  const { setKeys } = useKeys();
  const navigate = useNavigate();

  const accountPubRef = useRef<{ ed25519: string; x25519: string } | null>(null);
  const mailboxRef = useRef<MailboxSync | null>(null);
  const pollRef = useRef<number | null>(null);
  const processingRef = useRef(false);
  const realKeysRef = useRef<IdentityKeyPair | null>(null);
  const responseHashRef = useRef<string>('');

  const cleanup = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    mailboxRef.current?.close();
    mailboxRef.current = null;
  };

  // finalize adopts the approved identity per the chosen method. For passkey it must
  // run from a user gesture (the "Create passkey" button) because WebAuthn requires
  // user activation; for password the "Add device" button; single-use auto-runs.
  const finalize = async () => {
    const realKeys = realKeysRef.current;
    const acct = accountPubRef.current;
    if (!realKeys || !acct) return;

    // Cross-check the cloned PUBLIC keys against the directory. The import below is the
    // real proof: it signs the challenge with the cloned PRIVATE key.
    const edOk = toBase64(realKeys.ed25519Public) === acct.ed25519;
    const xOk = toBase64(realKeys.x25519Public) === acct.x25519;
    if (!edOk || !xOk) {
      const which = !edOk ? 'signing (Ed25519)' : 'encryption (X25519)';
      const dir = !edOk ? acct.ed25519 : acct.x25519;
      const got = !edOk ? toBase64(realKeys.ed25519Public) : toBase64(realKeys.x25519Public);
      setError(`The approving device sent a ${which} key that doesn't match what's registered for ${account} (directory ${dir.slice(0, 10)}… vs approved ${got.slice(0, 10)}…). Re-import or re-register ${account} there, then try again.`);
      return;
    }
    if (choice === 'password' && password.length < 6) { setError('choose a device password (at least 6 characters)'); return; }

    setFinalizing(true); setError('');
    try {
      const finishSession = async () => {
        const challenge = await importChallenge(account);
        const seed = realKeys.ed25519Private.slice(0, 32);
        const signature = await sign(seed, fromBase64(challenge.challenge_nonce));
        const { session_token } = await importIdentity({
          address: account,
          challenge_signature: toBase64(signature),
        });
        try { await mailboxRef.current?.deleteMessage(responseHashRef.current); } catch { /* ignore */ }
        cleanup();
        await setKeys(account, realKeys);
        setSession(account, session_token);
        navigate('/inbox');
      };

      if (choice === 'single') {
        // Temporary access: keep the working handle (tab-scoped, survives refresh) but
        // write NO encrypted keystore — no re-login material lands on this machine.
        // The shell recognises such a session by that absence; no flag to keep in sync.
        await finishSession();
        return;
      }

      const payloadBytes = new TextEncoder().encode(keyPairToPayloadJSON(realKeys));
      let bundle; let credentialId: string | undefined; let prfSalt: string | undefined;
      if (choice === 'passkey') {
        const enr = await createPasskeyPRF(account);
        bundle = await encryptKeysWithKey(payloadBytes, enr.aesKey);
        credentialId = enr.credentialId; prfSalt = enr.prfSalt;
      } else {
        bundle = await encryptKeys(payloadBytes, password);
      }
      await saveLocalKeystore(makeLocalKeystore({ address: account, kp: realKeys, bundle, authMethod: choice, credentialId, prfSalt }));
      await finishSession();
    } catch (err) {
      setFinalizing(false);
      setError(err instanceof Error ? err.message : 'failed to add this device');
      // A passkey that can't protect the keys (no PRF from whatever authenticator
      // answered) would otherwise strand the user here: the method cards are gone by
      // this step, so the only exit is Back — which discards the approval and costs a
      // whole new round trip plus a second approval on the trusted device. The
      // approved keys are still in realKeysRef, so offer the password path instead.
      if (choice === 'passkey' && approved) setPasskeyFailed(true);
    }
  };

  // Single-use needs no input, so adopt as soon as approval lands.
  useEffect(() => {
    if (approved && choice === 'single' && !finalizing) void finalize();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fires once when approval lands; keying on finalizing would re-run finalize after a failed attempt
  }, [approved]);

  const onPreviews = (previews: Preview[]) => {
    if (processingRef.current) return;
    const approval = previews.find(p => p.subject === SUBJECT_APPROVAL && p.senderAddress === account);
    if (!approval) return;
    processingRef.current = true;
    void (async () => {
      try {
        const full = await mailboxRef.current!.fetchFull(approval.hash);
        const realKeys = await extractCloneResponse(full.attachments);
        if (!realKeys) throw new Error('approval did not contain a key bundle');
        // The approver enrolled the key this pairing minted before it answered, so it is now this
        // browser's device key; whatever key was here before is not the one the mailbox knows.
        await commitPairingDeviceKey(account);
        realKeysRef.current = realKeys;
        responseHashRef.current = approval.hash;
        setApproved(true);
      } catch (err) {
        processingRef.current = false;
        setError(err instanceof Error ? err.message : 'failed to read the approval');
      }
    })();
  };

  const start = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!account.includes('@')) { setError('enter the account address you want to add this device to'); return; }
    setError('');
    try {
      // 1. Mint the single-use ephemeral identity (non-extractable working handles).
      const eph = await generateIdentityKeyPair();
      const ephAddr = ephemeralAddress();
      const ephWk = await importWorkingKeys(ephAddr, eph);

      // 2. Bind a short-lived session to the ephemeral address.
      const sess = await pairSession(ephAddr);
      setSessionToken(sess.session_token);

      // 3. Register the ephemeral record so its mailbox is fetchable. The ephemeral
      //    identity lives on the synthetic `pairing.local` domain, which has no relays
      //    of its own, so host its short-lived mailbox on the ACCOUNT's home relay:
      //    the account we're pairing to has real, reachable mailbox relays, and the
      //    origin device delivers the approval there. (Relay-hint placement is
      //    domain-scoped, so resolving the ephemeral address itself yields nothing.)
      const hints = await getRelayHints(account);
      if (!hints.relay_hints.length) throw new Error('no mailbox relay available for this account');
      const now = Math.floor(Date.now() / 1000);
      const recBytes = await buildEphemeralRecord(ephAddr, eph, hints.relay_hints[0], now);
      await pairRegister(toBase64(recBytes));

      // 4. Look up the account and compute the confirmation code.
      const acct = await lookupIdentity(account);
      accountPubRef.current = { ed25519: acct.ed25519_pub, x25519: acct.x25519_pub };
      setCode(await confirmationCode(account, eph.ed25519Public, eph.x25519Public));
      setApproved(false);
      setStep('verify');

      // 5. Build + seal the clone-request and STORE it into the account mailbox.
      // Mint this browser's own device key BEFORE asking, so the approver can enrol it in the
      // same breath as handing over the account keys. It is generated non-extractable, so only
      // its public half can travel — which is exactly what makes a copy of the account keys
      // insufficient to act as this device.
      //
      // Always a fresh key, so a browser that was removed comes back as a new device (the removed
      // key is refused for good), and it waits beside any current key until the approval lands.
      const deviceKey = await pairingDeviceKey(account);
      const att = await cloneRequestAttachment(eph, label || 'Web browser', now, deviceKey.publicKey);
      const envelope = await encryptSplit({
        version: 1,
        messageId: uuid(),
        threadId: uuid(),
        senderAddress: ephAddr,
        senderPublicKey: eph.ed25519Public,
        senderSignKey: ephWk.ed25519Sign,
        recipientAddress: account,
        sentAt: now,
        subject: SUBJECT_REQUEST,
        bodyText: 'A new device is requesting access to this identity.',
        attachments: [att],
        recipients: [{ deviceId: eph.deviceId, x25519Pub: fromBase64(acct.x25519_pub) }],
      });
      const envBytes = await encodeSplitEnvelope(envelope);
      const envHash = new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(envBytes)));
      const envSignature = await signWithKey(ephWk.ed25519Sign, envHash);
      await sendMessage({
        sender_address: ephAddr,
        sender_signature: toBase64(envSignature),
        envelope: toBase64(envBytes),
        recipient_address: account,
      });

      // 6. Poll the ephemeral mailbox for the account-signed approval.
      mailboxRef.current = new MailboxSync(ephWk, onPreviews, sess.session_token);
      const poll = () => mailboxRef.current?.list().catch(m => setError(m instanceof Error ? m.message : String(m)));
      poll();
      pollRef.current = window.setInterval(poll, 3000);
    } catch (err) {
      cleanup();
      setStep('form');
      setError(err instanceof Error ? err.message : 'failed to start pairing');
    }
  };

  const goBack = () => { cleanup(); processingRef.current = false; realKeysRef.current = null; setApproved(false); setError(''); setStep('form'); };

  return (
    <AuthShell
      title={step === 'form' ? 'Add this device' : 'Approve on a trusted device'}
      subtitle={step === 'form'
        ? 'Sign in from one of your existing devices to bring your identity here.'
        : "Open this mailbox on a device where you're already signed in, and type the last four digits of this code there."}
      note={step === 'form'
        ? "Your keys transfer securely between your own devices — we can't read your mail."
        : null}
      footer={step === 'form' ? <Link to="/login" style={linkStyle}>← Back to sign in</Link> : undefined}
    >
      {step === 'form' ? (
        <form onSubmit={start} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
          <EmailAddressField label="Account address" localPart={localPart} onLocalChange={setLocalPart} domain={domain} onDomainChange={setDomain} domains={domains} required />
          <Input label="Device label (optional)" type="text" value={label} onChange={e => setLabel(e.target.value)} placeholder="Chrome on MacBook" />

          <div>
            <div style={fieldLabelStyle}>How should this device sign in?</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {passkeyOk && (
                <ChoiceCard checked={choice === 'passkey'} onClick={() => setChoice('passkey')} icon="key" title="Passkey" badge="RECOMMENDED" desc="Unlock with your device biometrics. Nothing to remember." />
              )}
              <ChoiceCard checked={choice === 'password'} onClick={() => setChoice('password')} icon="lock" title="Password" desc="Save a locked copy of your keys here, unlocked by a password." />
              <ChoiceCard checked={choice === 'single'} onClick={() => setChoice('single')} icon="refresh" title="Single-use session" desc="For a shared computer. Nothing is saved — closing the tab signs you out." />
            </div>
          </div>

          {error && (
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
              <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
            </div>
          )}
          <Button type="submit" size="lg" fullWidth>Request access</Button>
        </form>
      ) : (
        <div>
          <button type="button" onClick={goBack} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, background: 'transparent', border: 'none', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', fontFamily: 'var(--font-sans)', cursor: 'pointer', padding: 0, marginBottom: 'var(--space-3)' }}>
            <Icon name="chevron-left" size={14} /> Back
          </button>

          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, marginBottom: 'var(--space-4)', padding: '5px 10px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', background: 'var(--surface-card)' }}>
            <span style={{ width: 7, height: 7, borderRadius: 999, background: 'var(--brand)' }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-body)' }}>{account}</span>
            {label.trim() && <span style={{ fontSize: 13, color: 'var(--text-subtle)' }}>· {label.trim()}</span>}
          </div>

          {/* The trusted device shows the leading groups and leaves the last one as an
              empty field (DeviceRequests), so the last group is highlighted here: it is
              the part that has to travel between the two screens by being read. */}
          <div style={{ fontSize: 'var(--text-xl)', fontWeight: 700, letterSpacing: 2, fontFamily: 'var(--font-mono)', color: 'var(--text-strong)' }}>
            <span style={{ color: 'var(--text-muted)' }}>{splitConfirmationCode(code).shown}-</span>
            <span>{splitConfirmationCode(code).typed}</span>
          </div>
          <div style={{ marginTop: 'var(--space-2)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
            Enter the last four digits on the device you're approving from.
          </div>

          <div style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
            <span className={approved ? '' : 'dmcn-pulse'} style={{ width: 8, height: 8, borderRadius: 999, background: approved ? 'var(--success)' : 'var(--brand)' }} />
            {approved ? 'Approved' : 'Waiting for approval…'}
          </div>

          {error && (
            <div style={{ marginTop: 'var(--space-4)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--danger)', fontSize: 'var(--text-sm)' }}>
              <Icon name="alert-triangle" size={15} style={{ marginTop: 1, flex: 'none' }} /><span>{error}</span>
            </div>
          )}

          {/* per-choice tail */}
          {choice === 'passkey' && (
            <div style={{ marginTop: 'var(--space-5)', paddingTop: 'var(--space-5)', borderTop: '1px solid var(--border-subtle)' }}>
              <p style={{ margin: '0 0 var(--space-3)', fontSize: 'var(--text-md)', color: 'var(--text-body)', lineHeight: 1.5 }}>
                Once approved, create a passkey so this device unlocks with biometrics.
              </p>
              <Button size="lg" fullWidth variant="secondary" disabled={!approved || finalizing} leftIcon={<Icon name="key" size={16} />} onClick={() => void finalize()}>
                {finalizing ? 'Adding…' : passkeyFailed ? 'Try the passkey again' : 'Create passkey'}
              </Button>
              {passkeyFailed && (
                <div style={{ marginTop: 'var(--space-3)' }}>
                  <Button size="lg" fullWidth variant="ghost" disabled={finalizing} onClick={() => { setPasskeyFailed(false); setError(''); setChoice('password'); }}>
                    Use a password instead
                  </Button>
                </div>
              )}
            </div>
          )}
          {choice === 'password' && (
            <div style={{ marginTop: 'var(--space-5)', paddingTop: 'var(--space-5)', borderTop: '1px solid var(--border-subtle)' }}>
              <label htmlFor="dpw" style={fieldLabelStyle}>Set a password for this device</label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <input id="dpw" type={showPass ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)} placeholder="Device password" autoComplete="new-password"
                  style={{ boxSizing: 'border-box', width: '100%', fontFamily: 'var(--font-sans)', fontSize: 15, color: 'var(--text-strong)', background: 'var(--surface-card)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', height: 40, padding: '0 40px 0 12px' }} />
                <button type="button" aria-label={showPass ? 'Hide password' : 'Show password'} onClick={() => setShowPass(s => !s)}
                  style={{ position: 'absolute', right: 6, width: 30, height: 30, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'transparent', border: 'none', color: 'var(--text-subtle)', cursor: 'pointer', borderRadius: 'var(--radius-sm)' }}>
                  <Icon name={showPass ? 'eye-off' : 'eye'} size={16} />
                </button>
              </div>
              <div style={{ marginTop: 'var(--space-3)' }}>
                <Button size="lg" fullWidth disabled={!approved || finalizing} onClick={() => void finalize()}>
                  {finalizing ? 'Adding…' : 'Add device'}
                </Button>
              </div>
            </div>
          )}
          {choice === 'single' && (
            <div style={{ marginTop: 'var(--space-5)', paddingTop: 'var(--space-5)', borderTop: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', lineHeight: 1.5 }}>
              <Icon name="shield" size={15} style={{ color: 'var(--brand)', flex: 'none', marginTop: 1 }} />
              <span>This is a single-use session. Nothing is stored here — closing the tab or signing out ends access.</span>
            </div>
          )}
        </div>
      )}
    </AuthShell>
  );
}
