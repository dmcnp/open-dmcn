// From a message in the mailbox to its entry in the file: open it as the reader would, sort its
// attachments into the sender's and the protocol's, check a bridged message's attestation, and
// write it. The pieces that decide the bytes are pure (mime.ts, mbox.ts); this is where they meet
// the client's own state.

import type { FullBody, Preview } from '../api/mailboxRest';
import { userAttachments } from '../userAttachments';
import { bridgeOriginalIndex, verifyBridgeAttestation } from '../crypto/bridgeAttest';
import { fromHex } from '../crypto/bytes';
import { originalMessageId, renderMessage, type BridgeVerdict, type ExportItem } from './mime';
import { mboxEntry } from './mbox';

/** The owner's state for a message, as the flags and labels providers hold it. */
export interface MessageState {
  read: boolean;
  starred: boolean;
  /** Label names, not ids: the file has to make sense without this account's label list. */
  labels: string[];
  /** 'Archive', a folder's name, or undefined for neither. */
  place?: string;
}

/**
 * exportEntry opens one message (fetched, decrypted, a bridged one's attestation checked) and
 * resolves to the function that writes it as its mbox entry, in chunks. The two are apart because
 * the export opens a message or two ahead but writes strictly in order, and writing is where
 * threading is settled: `ids` holds the Message-ID each message is exported under (by DMCN message
 * id), a bridged message records its original's own Message-ID there when it is written, and a
 * folder is written oldest first, so a reply written after its parent names it as written.
 */
export async function exportEntry(
  listed: Preview,
  open: (hash: string) => Promise<FullBody>,
  sent: boolean,
  state: (hash: string) => MessageState,
  ids: Map<string, string>,
): Promise<() => Uint8Array[]> {
  const full = await open(listed.hash);
  const row = full.row ?? listed;
  const originalAt = bridgeOriginalIndex(full.attachments);

  let bridge: BridgeVerdict | null = null;
  const original = originalAt >= 0 ? full.attachments[originalAt].content : undefined;
  if (original) {
    const pub = row.senderPublicKey ? fromHex(row.senderPublicKey) : null;
    const v = await verifyBridgeAttestation(full.attachments, pub);
    if (v) bridge = { verified: v.verified, spf: v.spf, dkim: v.dkim, dmarc: v.dmarc, reason: v.reason };
  }

  const s = state(row.hash);
  const item: ExportItem = {
    row,
    replyToId: full.replyToId ?? '',
    text: full.bodyText,
    html: full.htmlBody,
    attachments: userAttachments(full.attachments),
    original,
    bridge,
    sent,
    read: s.read,
    starred: s.starred,
    labels: s.labels,
    place: s.place,
    ids,
  };
  return () => {
    const real = original && originalMessageId(original);
    if (real && row.messageId) ids.set(row.messageId.toLowerCase(), real);
    return mboxEntry(row.senderAddress, row.sentAt, renderMessage(item));
  };
}
