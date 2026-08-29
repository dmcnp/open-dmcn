// A bridged legacy email's authentication attestation. A bridge runs SPF/DKIM/DMARC at
// ingest and signs the verdict into a BridgeClassificationRecord attachment; the recipient
// trusts that verdict only after confirming the bridge is one it trusts.
//
// The bridge is pure INFRASTRUCTURE — it has no DMCN email identity, so there is nothing to
// look up: everything needed is in the record plus a trust anchor. WHICH anchor, and where
// the check runs, is a property of the deployment (see lib/deployment.ts), so this module
// holds only the shape of the answer and the one rule both anchors share: an attestation is
// worth nothing until it is tied to the message carrying it.

import { deployment } from '../../deployment';

export const CLASSIFICATION_CONTENT_TYPE = 'application/x-dmcn-bridge-classification';

export enum BridgeTrustTier {
  Unspecified = 0,
  VerifiedLegacy = 1,
  UnverifiedLegacy = 2,
  Suspicious = 3,
}

export interface BridgeAttestation {
  verified: boolean; // signature valid AND the signer is a trusted bridge that authored this message
  trustTier: BridgeTrustTier; // bridge-asserted tier; meaningful only when verified
  smtpFrom: string; // original legacy sender, for display
  // The individual SPF/DKIM/DMARC verdicts behind trustTier. Carried so the reader can
  // say WHICH check did not pass rather than only that the tier fell short — the tier
  // requires DKIM AND DMARC to pass, so a message that authenticates perfectly well via
  // aligned SPF still lands in "unauthenticated", and that is worth being able to tell
  // apart from a genuine spoof.
  spf?: string;
  dkim?: string;
  dmarc?: string;
  reason?: string; // why verification failed
}

export interface AttachmentLike {
  contentType: string;
  content: Uint8Array;
}

// verifyBridgeAttestation inspects a decrypted message's attachments. It returns null when
// the message is not a bridged legacy email (no classification record), or a verdict
// describing whether the bridge's account of it can be trusted.
//
// messageSenderPub is the wrapped message's already-verified sender Ed25519 key. A bridged
// message is authored BY the bridge, so the verifier binds the classification to that key;
// without it a genuine attestation could be lifted off one message and stapled onto another,
// lending a bridge's verdict to mail the bridge never saw.
export async function verifyBridgeAttestation(
  attachments: AttachmentLike[],
  messageSenderPub: Uint8Array | null,
): Promise<BridgeAttestation | null> {
  const att = attachments.find((a) => a.contentType === CLASSIFICATION_CONTENT_TYPE);
  if (!att) return null; // not a bridged message

  try {
    return await deployment.verifyClassification(att.content, messageSenderPub);
  } catch {
    // Verifier unreachable or broken: fail closed to an unverified verdict. Never throw and
    // never a trusted badge — an unavailable check is not a passed one.
    return { verified: false, trustTier: BridgeTrustTier.Unspecified, smtpFrom: '', reason: 'verification unavailable' };
  }
}
