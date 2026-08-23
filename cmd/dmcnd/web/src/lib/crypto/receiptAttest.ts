// Client-side verification of a bridge DELIVERY RECEIPT — the signed confirmation the bridge
// returns to a DMCN sender after (attempting) SMTP delivery of an outbound-to-legacy message.
//
// Verified exactly like an inbound classification (see bridgeAttest.ts), and for the same reason:
// a bridge has no email address and no directory entry, so everything needed is in the record plus
// the domain root key published in DNS. Nothing here asks the server what to believe — a receipt
// saying "delivered" is only as good as the credential chain behind it, and that chain is checked
// in the browser.
//
// The bridge only sends a receipt for a FAILED delivery by default (a success receipt per message
// is noise), so in practice this renders bounces. It still verifies success the same way, because
// a self-hoster can turn success receipts on.
import { decodeDeliveryReceipt, decodeCredentialFromReceipt } from './protobuf';
import { verify } from './sign';
import { fromBase64 } from './keys';
import { DOMAIN_ROOT_PUB } from '../config';

export const RECEIPT_CONTENT_TYPE = 'application/x-dmcn-bridge-delivery-receipt';

// Must match identity.RoleBridge and identity.ctxCredential (Go).
const ROLE_BRIDGE = 'bridge';
const CRED_CTX: Uint8Array = new TextEncoder().encode('dmcn-credential-v1\0');

export interface DeliveryReceiptView {
  /** Signed by a key holding this domain's root-issued `bridge` credential. */
  verified: boolean;
  /** Bridge-asserted delivery outcome. Meaningful only when `verified`. */
  delivered: boolean;
  /** The legacy address the bridge delivered to (or tried to). */
  recipientEmail: string;
  /** Failure detail from the bridge, when it failed. */
  errorDetail?: string;
  /** Why verification failed, when it did. */
  reason?: string;
}

interface AttachmentLike {
  contentType: string;
  content: Uint8Array;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// verifyDeliveryReceipt inspects a decrypted message's attachments. Returns null when the message
// is not a delivery receipt, else a verdict describing whether it can be trusted and what it says.
export async function verifyDeliveryReceipt(
  attachments: AttachmentLike[],
  messageSenderPub: Uint8Array | null,
): Promise<DeliveryReceiptView | null> {
  const att = attachments.find(a => a.contentType === RECEIPT_CONTENT_TYPE);
  if (!att) return null; // not a delivery receipt

  let record, signableBytes;
  try {
    ({ record, signableBytes } = await decodeDeliveryReceipt(att.content));
  } catch {
    return { verified: false, delivered: false, recipientEmail: '', reason: 'malformed delivery receipt' };
  }
  const base = { delivered: record.success, recipientEmail: record.recipientEmail, errorDetail: record.errorDetail || undefined };

  // The receipt carries no bridge key of its own: the DMCN message that delivered it was signed by
  // the bridge, and that already-verified sender key is what the receipt must be signed by. Binding
  // to it is what stops a receipt being lifted from one message and stapled to another.
  if (!messageSenderPub) {
    return { ...base, verified: false, reason: 'no sender key to bind the receipt to' };
  }

  let sigOk = false;
  try {
    sigOk = await verify(messageSenderPub, signableBytes, record.bridgeSignature);
  } catch {
    sigOk = false; // malformed key/signature → unverified, never throw
  }
  if (!sigOk) return { ...base, verified: false, reason: 'invalid bridge signature' };

  if (!DOMAIN_ROOT_PUB) {
    return { ...base, verified: false, reason: 'no domain root key configured to verify the bridge against' };
  }
  let cred;
  try {
    cred = await decodeCredentialFromReceipt(att.content);
  } catch {
    cred = null;
  }
  if (!cred) return { ...base, verified: false, reason: 'no bridge credential' };

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

  if (!(cred.credential.roles ?? []).includes(ROLE_BRIDGE)) {
    return { ...base, verified: false, reason: 'credential does not carry the bridge role' };
  }
  // The credential is public — it travels in every record the bridge signs — so it must be FOR
  // the key that signed this one, or anyone could staple a real credential to their own receipt.
  if (!bytesEqual(cred.credential.subject ?? new Uint8Array(), messageSenderPub)) {
    return { ...base, verified: false, reason: 'bridge credential is for a different key' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (cred.credential.notAfter && now > cred.credential.notAfter) {
    return { ...base, verified: false, reason: 'bridge credential has expired' };
  }
  if (cred.credential.effectiveFrom && now < cred.credential.effectiveFrom) {
    return { ...base, verified: false, reason: 'bridge credential is not yet valid' };
  }

  return { ...base, verified: true };
}
