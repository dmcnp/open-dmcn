// A bridge DELIVERY RECEIPT — the signed confirmation the bridge returns to a DMCN sender
// after (attempting) SMTP delivery of an outbound-to-legacy message.
//
// Trusted exactly like an inbound classification, and against the same deployment-supplied
// anchor (see lib/deployment.ts). The bridge only sends a receipt for a FAILED delivery by
// default (a success receipt per message is noise), so in practice this renders bounces. It
// still verifies success the same way, because a self-hoster can turn success receipts on.

import { deployment } from '../../deployment';
import type { AttachmentLike } from './bridgeAttest';

export const RECEIPT_CONTENT_TYPE = 'application/x-dmcn-bridge-delivery-receipt';

export interface DeliveryReceiptView {
  verified: boolean; // signed by a trusted bridge
  delivered: boolean; // bridge-asserted: delivered vs failed (meaningful only when verified)
  recipientEmail: string; // the legacy address delivered to (or tried)
  errorDetail?: string; // failure detail from the bridge, when it failed
  reason?: string; // why verification failed
}

// verifyDeliveryReceipt inspects a decrypted message's attachments. Returns null when the
// message is not a delivery receipt, else a verdict describing whether it can be trusted and
// what it says.
//
// messageSenderPub is the receipt message's already-verified sender key — the bridge. The
// receipt carries no bridge key of its own, so binding to that key is the only thing that
// stops a receipt being lifted from one message and stapled to another.
export async function verifyDeliveryReceipt(
  attachments: AttachmentLike[],
  messageSenderPub: Uint8Array | null,
): Promise<DeliveryReceiptView | null> {
  const att = attachments.find((a) => a.contentType === RECEIPT_CONTENT_TYPE);
  if (!att) return null; // not a delivery receipt

  try {
    return await deployment.verifyReceipt(att.content, messageSenderPub);
  } catch {
    return { verified: false, delivered: false, recipientEmail: '', reason: 'verification unavailable' };
  }
}
