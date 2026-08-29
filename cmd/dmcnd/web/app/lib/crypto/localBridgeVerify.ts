// In-browser verification of a bridge's attestations, against the domain root key.
//
// This is the reference daemon's answer to lib/deployment.ts's verifyClassification /
// verifyReceipt. Nothing here asks the server what to believe: a bridge has no email address
// and no directory entry, so everything needed is in the record plus the domain's root
// Ed25519 key — which is public by construction, being what the domain's _dmcn DNS
// fingerprint commits to. An earlier version resolved a `bridge@<domain>` mailbox and read a
// bridge_capability flag off it, which made a trust decision depend on a live directory
// lookup the server could influence.
//
// The daemon never sees plaintext, so this runs entirely over the decrypted attachment.

import { decodeBridgeClassification, decodeCredentialFromClassification, decodeDeliveryReceipt, decodeCredentialFromReceipt } from './bridgeProtobuf';
import { verify } from '../../../src/lib/crypto/sign';
import { fromBase64 } from '../../../src/lib/crypto/keys';
import { envVal } from '../../../src/lib/config';

// This domain's root Ed25519 public key (base64). Public by construction — it is what the
// domain's _dmcn DNS fingerprint commits to. Read here rather than from shared config
// because it is this deployment's trust anchor, and no other deployment has one.
const DOMAIN_ROOT_PUB = envVal('DOMAIN_ROOT_PUB', '');
import { BridgeTrustTier, type BridgeAttestation } from '../../../src/lib/crypto/bridgeAttest';
import type { DeliveryReceiptView } from '../../../src/lib/crypto/receiptAttest';

// ROLE_BRIDGE mirrors identity.RoleBridge (Go).
const ROLE_BRIDGE = 'bridge';

// CRED_CTX domain-separates a credential signature. Must match identity.ctxCredential (Go):
// "dmcn-credential-v1\0".
const CRED_CTX: Uint8Array = new TextEncoder().encode('dmcn-credential-v1\0');

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
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

// verifyCredential checks a bridge credential carried in an attestation: issued by this
// domain's root, currently valid, granting the bridge role, and FOR the given key. A
// credential is public — it travels in every message the bridge signs — so without that last
// check anyone could staple a real one to their own record. Returns null when it holds.
async function verifyCredential(
  cred: { credential: { subject?: Uint8Array; roles?: string[]; issuerPub?: Uint8Array; signature: Uint8Array; notAfter?: number; effectiveFrom?: number }; signableBytes: Uint8Array } | null,
  signerKey: Uint8Array,
): Promise<string | null> {
  if (!DOMAIN_ROOT_PUB) return 'no domain root key configured to verify the bridge against';
  if (!cred) return 'no bridge credential';

  let rootPub: Uint8Array;
  try {
    rootPub = fromBase64(DOMAIN_ROOT_PUB);
  } catch {
    return 'malformed domain root key';
  }
  if (!bytesEqual(cred.credential.issuerPub ?? new Uint8Array(), rootPub)) {
    return 'bridge credential was not issued by this domain';
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
  if (!credOk) return 'bridge credential signature invalid';
  if (!(cred.credential.roles ?? []).includes(ROLE_BRIDGE)) {
    return 'credential does not carry the bridge role';
  }
  if (!bytesEqual(cred.credential.subject ?? new Uint8Array(), signerKey)) {
    return 'bridge credential is for a different key';
  }
  const now = Math.floor(Date.now() / 1000);
  if (cred.credential.notAfter && now > cred.credential.notAfter) return 'bridge credential has expired';
  if (cred.credential.effectiveFrom && now < cred.credential.effectiveFrom) return 'bridge credential is not yet valid';
  return null;
}

// verifyClassificationLocal is lib/deployment.ts's verifyClassification for this build.
export async function verifyClassificationLocal(
  classification: Uint8Array,
  messageSenderPub: Uint8Array | null,
): Promise<BridgeAttestation> {
  let record, signableBytes;
  try {
    ({ record, signableBytes } = await decodeBridgeClassification(classification));
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

  // 2. That signer must be the author of the message carrying it, or a genuine verdict
  //    could be lifted off one message and stapled onto another.
  if (messageSenderPub && !bytesEqual(record.bridgePublicKey, messageSenderPub)) {
    return { ...base, verified: false, reason: 'classification signer is not the message author' };
  }

  // 3. And it must hold a bridge credential from this domain's root.
  let cred;
  try {
    cred = await decodeCredentialFromClassification(classification);
  } catch {
    cred = null;
  }
  const credErr = await verifyCredential(cred, record.bridgePublicKey);
  if (credErr) return { ...base, verified: false, reason: credErr };

  return { ...base, verified: true };
}

// verifyReceiptLocal is lib/deployment.ts's verifyReceipt for this build.
export async function verifyReceiptLocal(
  receipt: Uint8Array,
  messageSenderPub: Uint8Array | null,
): Promise<DeliveryReceiptView> {
  let record, signableBytes;
  try {
    ({ record, signableBytes } = await decodeDeliveryReceipt(receipt));
  } catch {
    return { verified: false, delivered: false, recipientEmail: '', reason: 'malformed delivery receipt' };
  }
  const base = { delivered: record.success, recipientEmail: record.recipientEmail, errorDetail: record.errorDetail || undefined };

  // The receipt carries no bridge key of its own: the DMCN message that delivered it was
  // signed by the bridge, and that already-verified sender key is what it must be signed by.
  if (!messageSenderPub) {
    return { ...base, verified: false, reason: 'no sender key to bind the receipt to' };
  }

  let sigOk = false;
  try {
    sigOk = await verify(messageSenderPub, signableBytes, record.bridgeSignature);
  } catch {
    sigOk = false;
  }
  if (!sigOk) return { ...base, verified: false, reason: 'invalid bridge signature' };

  let cred;
  try {
    cred = await decodeCredentialFromReceipt(receipt);
  } catch {
    cred = null;
  }
  const credErr = await verifyCredential(cred, messageSenderPub);
  if (credErr) return { ...base, verified: false, reason: credErr };

  return { ...base, verified: true };
}
