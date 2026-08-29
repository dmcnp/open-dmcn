// Protobuf codecs for a bridge's signed attestations.
//
// Here rather than in the shared crypto/protobuf.ts because only THIS deployment decodes
// them: it verifies a bridge's attestation in the browser (see localBridgeVerify.ts), while a
// deployment that verifies server-side never parses one at all. Keeping them here is also
// what lets the shared bundle stay core-only.

import { dmcn } from '@proto';

// --- Bridge classification record (signed legacy-auth attestation) ---

export interface BridgeClassificationFields {
  bridgeAddress: string;
  bridgePublicKey: Uint8Array;
  smtpFrom: string;
  smtpSenderIp: string;
  spfResult: number;
  dkimResult: number;
  dmarcResult: number;
  reputationScore: number;
  trustTier: number;
  classifiedAt: number;
  bridgeSignature: Uint8Array;
}

// decodeBridgeClassification decodes a BridgeClassificationRecord attachment and
// returns both the parsed fields and the exact bytes the bridge signed over
// (the record minus bridge_signature). signableBytes are produced by re-encoding
// the decoded message with the signature field removed: pbjs writes fields in
// ascending field-number order and only those present on the wire, which is
// byte-identical to Go's deterministic signableBytes() (internal/bridge/types.go).
export async function decodeBridgeClassification(
  data: Uint8Array
): Promise<{ record: BridgeClassificationFields; signableBytes: Uint8Array }> {
  const T = dmcn.bridge.BridgeClassificationRecord;
  const msg = T.decode(data);
  // longs:Number keeps classified_at a plain number; bytes stay Uint8Array.
  const record = T.toObject(msg, { longs: Number }) as BridgeClassificationFields;
  // Remove the signature AND the credential, then re-encode → the signed-over bytes.
  //
  // The credential (field 12) must come out as well: Go signs fields 1-10 only, deliberately, so
  // that a bridge credential can be re-issued without invalidating every attestation it ever
  // made. Leaving it in here would make the browser compute different signed bytes than the
  // bridge did, and every bridged message would render as forged.
  const own = msg as unknown as Record<string, unknown>;
  delete own.bridgeSignature;
  delete own.bridgeCredential;
  const signableBytes = T.encode(msg).finish() as Uint8Array;
  return { record, signableBytes };
}

// CredentialFields is the subset of a dmcn.identity.Credential this client reads.
export interface CredentialFields {
  subject: Uint8Array;
  domain: string;
  roles: string[];
  issuerPub: Uint8Array;
  signature: Uint8Array;
  notAfter?: number;
  effectiveFrom?: number;
}

// decodeCredentialFromClassification pulls the bridge credential out of a classification record
// and returns its fields alongside the exact bytes its issuer signed (the credential minus its
// signature), so the browser can verify it against a domain root key.
export async function decodeCredentialFromClassification(
  data: Uint8Array
): Promise<{ credential: CredentialFields; signableBytes: Uint8Array } | null> {
  const T = dmcn.bridge.BridgeClassificationRecord;
  const msg = T.decode(data) as unknown as Record<string, unknown>;
  return extractCredential(msg.bridgeCredential);
}

// decodeCredentialFromReceipt is the same extraction for a delivery receipt. Both records
// carry the bridge's credential in the identical shape, and both are verified the same way.
export async function decodeCredentialFromReceipt(
  data: Uint8Array
): Promise<{ credential: CredentialFields; signableBytes: Uint8Array } | null> {
  const T = dmcn.bridge.BridgeDeliveryReceipt;
  const msg = T.decode(data) as unknown as Record<string, unknown>;
  return extractCredential(msg.bridgeCredential);
}

function extractCredential(cred: unknown): { credential: CredentialFields; signableBytes: Uint8Array } | null {
  if (!cred) return null;
  const C = dmcn.identity.Credential;
  const credential = C.toObject(cred as never, { longs: Number }) as unknown as CredentialFields;
  // Same trick as above: drop the signature own-property and re-encode.
  delete (cred as Record<string, unknown>).signature;
  const signableBytes = C.encode(cred as never).finish() as Uint8Array;
  return { credential, signableBytes };
}

// DeliveryReceiptFields mirrors dmcn.bridge.BridgeDeliveryReceipt.
export interface DeliveryReceiptFields {
  originalMessageId: Uint8Array;
  recipientEmail: string;
  bridgeAddress: string;
  deliveredAt: number;
  success: boolean;
  errorDetail: string;
  bridgeSignature: Uint8Array;
}

// decodeDeliveryReceipt returns the receipt's fields plus the exact bytes the bridge signed
// (fields 1-6). Both the signature (7) and the credential (8) come out, matching Go's
// signableBytes — the credential is excluded there so a re-issued credential does not
// invalidate every receipt the bridge ever wrote.
export async function decodeDeliveryReceipt(
  data: Uint8Array
): Promise<{ record: DeliveryReceiptFields; signableBytes: Uint8Array }> {
  const T = dmcn.bridge.BridgeDeliveryReceipt;
  const msg = T.decode(data);
  const record = T.toObject(msg, { longs: Number }) as unknown as DeliveryReceiptFields;
  const own = msg as unknown as Record<string, unknown>;
  delete own.bridgeSignature;
  delete own.bridgeCredential;
  const signableBytes = T.encode(msg).finish() as Uint8Array;
  return { record, signableBytes };
}
