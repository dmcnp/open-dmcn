// The attachments a person sent, as opposed to the ones the protocol carries alongside them.
//
// Shared by the reader, which lists them, and the search index, which indexes their names: a
// search for "*.eml" should not find every bridged message by the raw source it carries.

import { bridgeOriginalIndex, CLASSIFICATION_CONTENT_TYPE } from './crypto/bridgeAttest';
import { RECEIPT_CONTENT_TYPE } from './crypto/receiptAttest';
import { deployment } from '@deployment';

// System attachments carried for protocol purposes are consumed elsewhere and hidden
// from the user-facing attachment list: the bridge attestation and delivery receipt, and
// whatever control payloads this deployment carries. The bridge's raw legacy source is
// hidden too, but by its slot (bridgeOriginalIndex) rather than its type — an email
// forwarded as an attachment is message/rfc822 as well, and is the reader's to see. The
// raw source is offered through "Show original" instead.
// Built on demand, not at module load: `deployment` imports the screens it contributes, so
// reading it while THIS module is being evaluated would depend on which side of that cycle
// loaded first. A function has no such ordering to get wrong.
function internalAttachmentTypes(): Set<string> {
  return new Set<string>([
    CLASSIFICATION_CONTENT_TYPE,
    RECEIPT_CONTENT_TYPE,
    ...deployment.internalAttachmentTypes,
  ]);
}
export function userAttachments<A extends { contentType: string; filename: string }>(all: A[]): A[] {
  const internal = internalAttachmentTypes();
  const original = bridgeOriginalIndex(all);
  return all.filter((a, i) => i !== original && !internal.has(a.contentType));
}
