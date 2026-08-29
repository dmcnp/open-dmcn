// Client-side verification of a bridged legacy email's authentication attestation.
//
// A bridge runs SPF/DKIM/DMARC when legacy mail arrives and signs the verdict into a
// BridgeClassificationRecord attachment. The recipient trusts that verdict only after confirming,
// here in the browser, that:
//   1. the record is signed by the key it carries, and
//   2. that key holds a credential, signed by the domain's root, saying it may act as a bridge.
//
// A bridge has NO email address and no directory entry. It is infrastructure — a peer that
// translates between SMTP and DMCN — so there is nothing to look up: everything needed is in the
// record plus the domain root key, which is public and published in DNS as the domain's fingerprint.
// The previous version resolved a `bridge@<domain>` mailbox and read a `bridge_capability` flag off
// it, which made a trust decision depend on a live directory lookup the server could influence.
//
// The web backend never sees plaintext, so this runs entirely client-side over the decrypted
// attachment.
import { decodeBridgeClassification, decodeCredentialFromClassification } from './protobuf';
import { verify } from './sign';
import { fromBase64 } from './keys';
import { DOMAIN_ROOT_PUB } from '../config';

export const CLASSIFICATION_CONTENT_TYPE = 'application/x-dmcn-bridge-classification';

// ROLE_BRIDGE mirrors identity.RoleBridge (Go).
const ROLE_BRIDGE = 'bridge';

// CRED_CTX domain-separates a credential signature. Must match identity.ctxCredential (Go):
// "dmcn-credential-v1\0".
const CRED_CTX: Uint8Array = new TextEncoder().encode('dmcn-credential-v1\0');

export enum BridgeTrustTier {
  Unspecified = 0,
  VerifiedLegacy = 1,
  UnverifiedLegacy = 2,
  Suspicious = 3,
}

export interface BridgeAttestation {
  verified: boolean; // signature valid AND the signer holds a root-signed bridge credential
  trustTier: BridgeTrustTier; // bridge-asserted tier; meaningful only when verified
  smtpFrom: string; // original legacy sender, for display
  // The individual SPF/DKIM/DMARC verdicts behind trustTier. Carried so the reader can
  // say WHICH check did not pass rather than only that the tier fell short — the tier
  // requires DKIM AND DMARC to pass, so a message that authenticates perfectly well via
  // aligned SPF still lands in "unauthenticated", and that is worth being able to tell
  // apart from a genuine spoof. Meaningful only when verified.
  spf?: string;
  dkim?: string;
  dmarc?: string;
  reason?: string; // why verification failed
}

// The three verdict vocabularies match Go's SPFResult/DKIMResult/DMARCResult String()
// (internal/bridge/types.go), which in turn follow RFC 7208 — so a reader can compare
// what this shows against a Received-SPF header or another MTA's verdict with no
// translation table. An absent field means the enum was 0, which is "none" in all three.
function spfString(v: number | undefined): string {
  switch (v) {
    case 1: return 'pass';
    case 2: return 'fail';
    case 3: return 'softfail';
    case 4: return 'neutral';
    default: return 'none';
  }
}
function dkimString(v: number | undefined): string {
  switch (v) {
    case 1: return 'pass';
    case 2: return 'fail';
    default: return 'none';
  }
}
function dmarcString(v: number | undefined): string {
  switch (v) {
    case 1: return 'pass';
    case 2: return 'fail';
    default: return 'none';
  }
}

interface AttachmentLike {
  contentType: string;
  content: Uint8Array;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// verifyBridgeAttestation inspects a decrypted message's attachments. It returns null when the
// message is not a bridged legacy email (no classification record), or a verdict describing
// whether the bridge's account of it can be trusted.
// messageSenderPub is the wrapped message's already-verified sender Ed25519 key. A bridged
// message is authored BY the bridge, so the classification's bridge key must be that same key
// — otherwise a genuine attestation could be lifted off one message and stapled onto another,
// lending a bridge's SPF/DKIM/DMARC verdict to mail the bridge never saw. Mirrors the binding
// verifyDeliveryReceipt already makes, and Go's check in bridge/attest.go's caller.
export async function verifyBridgeAttestation(
  attachments: AttachmentLike[],
  messageSenderPub?: Uint8Array | null,
): Promise<BridgeAttestation | null> {
  const att = attachments.find((a) => a.contentType === CLASSIFICATION_CONTENT_TYPE);
  if (!att) return null; // not a bridged message

  let record, signableBytes;
  try {
    ({ record, signableBytes } = await decodeBridgeClassification(att.content));
  } catch {
    return { verified: false, trustTier: BridgeTrustTier.Unspecified, smtpFrom: '', reason: 'malformed classification record' };
  }

  const base = {
    trustTier: record.trustTier as BridgeTrustTier,
    smtpFrom: record.smtpFrom,
    spf: spfString(record.spfResult),
    dkim: dkimString(record.dkimResult),
    dmarc: dmarcString(record.dmarcResult),
  };

  // 1. The record must be signed by the key it carries.
  let sigOk = false;
  try {
    sigOk = await verify(record.bridgePublicKey, signableBytes, record.bridgeSignature);
  } catch {
    sigOk = false; // malformed key/signature → unverified, never throw
  }
  if (!sigOk) return { ...base, verified: false, reason: 'invalid bridge signature' };

  // 1b. The signer must be the author of the message carrying it (see the note above).
  if (messageSenderPub && !bytesEqual(record.bridgePublicKey, messageSenderPub)) {
    return { ...base, verified: false, reason: 'classification signer is not the message author' };
  }

  // 2. That key must hold a bridge credential from this domain's root. Without a configured root
  //    there is nothing to check against, and saying "verified" would be a lie.
  if (!DOMAIN_ROOT_PUB) {
    return { ...base, verified: false, reason: 'no domain root key configured to verify the bridge against' };
  }
  let cred;
  try {
    cred = await decodeCredentialFromClassification(att.content);
  } catch {
    cred = null;
  }
  if (!cred) return { ...base, verified: false, reason: 'no bridge credential' };

  // The credential's own signature, by the domain root.
  let rootPub: Uint8Array;
  try {
    rootPub = fromBase64(DOMAIN_ROOT_PUB);
  } catch {
    return { ...base, verified: false, reason: 'malformed domain root key' };
  }
  if (!bytesEqual(cred.credential.issuerPub ?? new Uint8Array(), rootPub)) {
    return { ...base, verified: false, reason: 'bridge credential was not issued by this domain' };
  }
  const credBytes = new Uint8Array(CRED_CTX.length + cred.signableBytes.length);
  credBytes.set(CRED_CTX, 0);
  credBytes.set(cred.signableBytes, CRED_CTX.length);
  let credOk = false;
  try {
    credOk = await verify(rootPub, credBytes, cred.credential.signature);
  } catch {
    credOk = false;
  }
  if (!credOk) return { ...base, verified: false, reason: 'bridge credential signature invalid' };

  // 3. It must actually grant the bridge role — a routing or address credential is not authority
  //    to vouch for legacy mail.
  if (!(cred.credential.roles ?? []).includes(ROLE_BRIDGE)) {
    return { ...base, verified: false, reason: 'credential does not carry the bridge role' };
  }
  // 4. And it must be FOR the key that signed this record. A credential is public — it travels in
  //    every message the bridge signs — so without this anyone could staple a real one to their own.
  if (!bytesEqual(cred.credential.subject ?? new Uint8Array(), record.bridgePublicKey)) {
    return { ...base, verified: false, reason: 'bridge credential is for a different key' };
  }
  // 5. Validity window, when the issuer set one.
  const now = Math.floor(Date.now() / 1000);
  if (cred.credential.notAfter && now > cred.credential.notAfter) {
    return { ...base, verified: false, reason: 'bridge credential has expired' };
  }
  if (cred.credential.effectiveFrom && now < cred.credential.effectiveFrom) {
    return { ...base, verified: false, reason: 'bridge credential is not yet valid' };
  }

  return { ...base, verified: true };
}
