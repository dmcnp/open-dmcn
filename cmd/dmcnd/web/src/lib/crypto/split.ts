// Split header/body message crypto (Phase 2), parity with internal/core/message/split.go.
//
// A message is split into a small, independently-signed header (preview) and a
// large body, both sealed with one per-message CEK. The recipient decrypts +
// verifies the header to render an inbox row without the body, then fetches and
// verifies the body (against the signed body_hash) on open.

import { aesGcmEncrypt, wrapCEK, selectSizeClass, padPayload, type RecipientInfo } from './encrypt';
import { unwrapCEK, unpadPayload, aesGcmDecrypt } from './decrypt';
import { headerAAD, bodyAAD, normalizeKDF, PRODUCER_KDF } from './sealVersion';
import { signWithKey, verify } from './sign';
import { toPlainText } from '../html/toPlainText';
import {
  encodeMessageHeader,
  encodeSignedHeader,
  decodeSignedHeader,
  encodeMessageContent,
  decodeMessageContent,
  type MessageHeaderFields,
} from './protobuf';
import { bufferSource } from './bytes';

// Domain separation tag for the header signature (matches ctxMsgHeader in Go).
const CTX_MSG_HEADER = (() => {
  const tag = new TextEncoder().encode('dmcn-msg-header-v1');
  const out = new Uint8Array(tag.length + 1); // trailing 0x00 NUL
  out.set(tag, 0);
  return out;
})();
const SNIPPET_MAX = 140;

export interface SplitEnvelope {
  version: number;
  messageId: Uint8Array;
  createdAt: number;
  recipients: Array<{
    deviceId: Uint8Array;
    recipientXPub: Uint8Array;
    ephemeralXPub: Uint8Array;
    wrappedCek: Uint8Array;
    cekNonce: Uint8Array;
    cekTag: Uint8Array;
    kdf?: number;
  }>;
  encryptedHeader: Uint8Array;
  headerNonce: Uint8Array;
  headerTag: Uint8Array;
  headerSizeClass: number;
  encryptedBody: Uint8Array;
  bodyNonce: Uint8Array;
  bodyTag: Uint8Array;
  bodySizeClass: number;
  bodyContentAddress: Uint8Array; // cleartext CIDv1 of the body blob
}

export interface AttachmentInput {
  attachmentId: Uint8Array; // 16
  filename: string;
  contentType: string;
  sizeBytes: number;
  contentHash: Uint8Array; // 32, SHA-256 of content
  content: Uint8Array;
  // Set on parts embedded in the HTML body: contentId is the bare MIME Content-ID the
  // body references as <img src="cid:…"> and disposition is 'inline'. Omitted for an
  // ordinary attachment, which is then listed for download rather than rendered.
  contentId?: string;
  disposition?: string;
}

export interface ComposeInput {
  version: number;
  messageId: Uint8Array; // 16
  threadId: Uint8Array; // 16
  senderAddress: string;
  senderPublicKey: Uint8Array; // ed25519 public (32)
  senderSignKey: CryptoKey; // non-extractable Ed25519 handle for signing the header
  recipientAddress: string;
  // Full recipient lists (signed, visible to all). to/cc are identical across every
  // copy; bcc must be [] for recipient copies and only populated on the sender's own
  // Sent self-copy — the CALLER decides per copy, encryptSplit just forwards.
  to?: string[];
  cc?: string[];
  bcc?: string[];
  // 16-byte header replyToId: the messageId of the message this replies to. Omitted for
  // a non-reply — encodeMessageHeader then emits the required zero-filled 16 bytes.
  replyToId?: Uint8Array;
  sentAt: number; // Unix seconds
  subject: string;
  bodyText: string;
  // The optional text/html rendering of bodyText. It rides in MessageContent.alternatives;
  // the primary body stays text/plain so snippet/body_size keep their meaning and a
  // text-only reader (or the trust-gated plain-text peek) always has something to show.
  bodyHtml?: string;
  attachments?: AttachmentInput[];
  recipients: RecipientInfo[];
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data)));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// bodyContentAddress is the CIDv1(raw, sha2-256) of the body blob
// (body_nonce||encrypted_body||body_tag): 0x01 0x55 0x12 0x20 || SHA-256(blob).
// Byte-for-byte parity with Go message.ComputeBodyContentAddress — pinned by parityvector.test.ts.
export async function bodyContentAddress(nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Promise<Uint8Array> {
  const digest = await sha256(concat(concat(nonce, ciphertext), tag));
  const out = new Uint8Array(36);
  out.set([0x01, 0x55, 0x12, 0x20], 0); // CIDv1 / raw codec / sha2-256 / length 32
  out.set(digest, 4);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// snippetOf returns the longest valid-UTF-8 prefix of the first SNIPPET_MAX bytes
// of a text body (parity with Go snippetOf — never splits a multibyte rune).
//
// The prefix IS the contract (SPEC.md), not a choice this composer makes: a producer derives
// the snippet from the body it is sealing. Nothing binds the two the way body_hash binds the
// body, so a reader holding the body can re-derive and compare — Go's message.VerifySnippet.
export function snippetOf(contentType: string, content: Uint8Array): string {
  if (contentType !== 'text/plain') return '';
  let s = content.length > SNIPPET_MAX ? content.slice(0, SNIPPET_MAX) : content;
  while (s.length > 0) {
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(s);
    } catch {
      s = s.slice(0, s.length - 1);
    }
  }
  return '';
}

// encryptSplit builds a signed header + body sealed under one CEK and returns the
// split envelope. The caller encodes it, hashes it, and signs the hash for STORE.
export async function encryptSplit(input: ComposeInput): Promise<SplitEnvelope> {
  const bodyContent = new TextEncoder().encode(input.bodyText);
  const attachments = input.attachments ?? [];
  // multipart/alternative analog: the primary body is always text/plain; an HTML
  // rendering (when the composer produced one) is the richer alternative.
  const alternatives = input.bodyHtml
    ? [{ contentType: 'text/html', content: new TextEncoder().encode(input.bodyHtml) }]
    : undefined;

  // Body (content) → canonical bytes → body_hash commitment. body_hash therefore
  // commits to BOTH renderings, so neither can be swapped without breaking the header.
  const contentBytes = await encodeMessageContent({
    body: { contentType: 'text/plain', content: bodyContent },
    attachments,
    alternatives,
  });
  const bodyHash = await sha256(contentBytes);

  // Seal the body first under a fresh CEK so it can be content-addressed; the
  // address is then committed in the header and covered by the header signature.
  const cek = crypto.getRandomValues(new Uint8Array(32));

  const bClass = selectSizeClass(contentBytes.length);
  const b = await aesGcmEncrypt(cek, padPayload(contentBytes, bClass), bodyAAD(PRODUCER_KDF));
  const addr = await bodyContentAddress(b.nonce, b.ciphertext, b.tag);

  // Header, signed independently with the domain-separation tag. It commits to
  // both the plaintext (bodyHash) and the ciphertext blob (bodyContentAddress).
  const header: MessageHeaderFields = {
    version: input.version,
    messageId: input.messageId,
    threadId: input.threadId,
    replyToId: input.replyToId,
    senderAddress: input.senderAddress,
    senderPublicKey: input.senderPublicKey,
    recipientAddress: input.recipientAddress,
    sentAt: input.sentAt,
    subject: input.subject,
    attachmentCount: attachments.length,
    bodySize: bodyContent.length,
    snippet: snippetOf('text/plain', bodyContent),
    bodyHash,
    bodyContentAddress: addr,
    to: input.to,
    cc: input.cc,
    bcc: input.bcc,
  };
  const headerBytes = await encodeMessageHeader(header);
  const signature = await signWithKey(input.senderSignKey, concat(CTX_MSG_HEADER, headerBytes));
  const signedHeaderBytes = await encodeSignedHeader({ header, senderSignature: signature });

  const hClass = selectSizeClass(signedHeaderBytes.length);
  const h = await aesGcmEncrypt(cek, padPayload(signedHeaderBytes, hClass), headerAAD(PRODUCER_KDF));

  const recipients = await Promise.all(input.recipients.map(r => wrapCEK(cek, r)));

  return {
    version: 2,
    messageId: input.messageId,
    createdAt: input.sentAt,
    recipients,
    encryptedHeader: h.ciphertext,
    headerNonce: h.nonce,
    headerTag: h.tag,
    headerSizeClass: hClass,
    encryptedBody: b.ciphertext,
    bodyNonce: b.nonce,
    bodyTag: b.tag,
    bodySizeClass: bClass,
    bodyContentAddress: addr,
  };
}

export interface MailboxEntryLike {
  recipients: Array<{
    recipientXPub: Uint8Array;
    ephemeralXPub: Uint8Array;
    wrappedCek: Uint8Array;
    cekNonce: Uint8Array;
    cekTag: Uint8Array;
    kdf?: number;
  }>;
  encryptedHeader: Uint8Array;
  headerNonce: Uint8Array;
  headerTag: Uint8Array;
}

export interface MailboxBodyLike {
  encryptedBody: Uint8Array;
  bodyNonce: Uint8Array;
  bodyTag: Uint8Array;
}

function findRecipient(
  recipients: MailboxEntryLike['recipients'],
  x25519Pub: Uint8Array
) {
  const rec = recipients.find(r => bytesEqual(new Uint8Array(r.recipientXPub), x25519Pub));
  if (!rec) throw new Error('recipient not found in envelope');
  return {
    recipientXPub: new Uint8Array(rec.recipientXPub),
    ephemeralXPub: new Uint8Array(rec.ephemeralXPub),
    wrappedCek: new Uint8Array(rec.wrappedCek),
    cekNonce: new Uint8Array(rec.cekNonce),
    cekTag: new Uint8Array(rec.cekTag),
    // Carried out because the header and body blobs' additional data is keyed on the same
    // generation: it comes from the record, never from a guess.
    kdf: normalizeKDF(rec.kdf),
  };
}

// decryptHeader unwraps the CEK, decrypts the header, and verifies its signature.
// The returned header is a trustworthy preview (its signature commits to bodyHash).
export async function decryptHeader(
  entry: MailboxEntryLike,
  x25519Derive: CryptoKey,
  x25519Pub: Uint8Array
): Promise<MessageHeaderFields> {
  const rec = findRecipient(entry.recipients, x25519Pub);
  const cek = await unwrapCEK(rec, x25519Derive, x25519Pub);
  const padded = await aesGcmDecrypt(
    cek,
    new Uint8Array(entry.headerNonce),
    new Uint8Array(entry.encryptedHeader),
    new Uint8Array(entry.headerTag),
    headerAAD(rec.kdf)
  );
  const sh = await decodeSignedHeader(unpadPayload(padded));

  const signable = concat(CTX_MSG_HEADER, await encodeMessageHeader(sh.header));
  const ok = await verify(
    new Uint8Array(sh.header.senderPublicKey),
    signable,
    new Uint8Array(sh.senderSignature)
  );
  if (!ok) throw new Error('header signature verification failed');
  return sh.header;
}

// decryptBody decrypts the body and verifies it against the (already-verified)
// header's bodyHash.
export interface DecryptedAttachment {
  filename: string;
  contentType: string;
  content: Uint8Array;
  contentId: string;   // bare MIME Content-ID (inline parts referenced by cid:); '' otherwise
  disposition: string; // 'inline' | 'attachment' | ''
}

export async function decryptBody(
  entry: MailboxEntryLike,
  body: MailboxBodyLike,
  header: MessageHeaderFields,
  x25519Derive: CryptoKey,
  x25519Pub: Uint8Array
): Promise<{ contentType: string; content: Uint8Array; bodyText: string; htmlBody?: string; attachments: DecryptedAttachment[] }> {
  const rec = findRecipient(entry.recipients, x25519Pub);
  const cek = await unwrapCEK(rec, x25519Derive, x25519Pub);
  const padded = await aesGcmDecrypt(
    cek,
    new Uint8Array(body.bodyNonce),
    new Uint8Array(body.encryptedBody),
    new Uint8Array(body.bodyTag),
    bodyAAD(rec.kdf)
  );
  const contentBytes = unpadPayload(padded);

  const got = await sha256(contentBytes);
  if (!bytesEqual(got, new Uint8Array(header.bodyHash))) {
    throw new Error('body does not match header body_hash');
  }

  // Content-address bind: the (signature-verified) header commits to the exact
  // ciphertext blob. Skipped when the header predates the feature (empty address).
  if (header.bodyContentAddress && header.bodyContentAddress.length > 0) {
    const addr = await bodyContentAddress(
      new Uint8Array(body.bodyNonce),
      new Uint8Array(body.encryptedBody),
      new Uint8Array(body.bodyTag)
    );
    if (!bytesEqual(addr, new Uint8Array(header.bodyContentAddress))) {
      throw new Error('body does not match header body_content_address');
    }
  }

  const content = await decodeMessageContent(contentBytes);
  const raw = new Uint8Array(content.body.content);

  // body + alternatives = the multipart/alternative parts. bodyText is the text/plain
  // rendering (the primary body, or a text/plain alternative); htmlBody is the text/html
  // part if any. Text-only clients read bodyText; the reader prefers htmlBody when trusted.
  const parts = [content.body, ...(content.alternatives ?? [])];
  const textPart = parts.find(p => p.contentType === 'text/plain');
  const htmlPart = parts.find(p => p.contentType === 'text/html');
  const htmlBody = htmlPart ? new TextDecoder().decode(new Uint8Array(htmlPart.content)) : undefined;
  // No text/plain part at all — legacy mail that shipped HTML only, wrapped by a bridge
  // predating the bridge-side rendering. Render the HTML down to text rather than handing
  // the reader the markup as its "plain text": the plain-text peek exists precisely for a
  // sender whose HTML we refuse to render, and showing the source there is unreadable.
  const bodyText = textPart
    ? new TextDecoder().decode(new Uint8Array(textPart.content))
    : htmlBody !== undefined
      ? toPlainText(htmlBody)
      : new TextDecoder().decode(raw);

  const attachments: DecryptedAttachment[] = (content.attachments ?? []).map(a => ({
    filename: a.filename,
    contentType: a.contentType,
    content: new Uint8Array(a.content),
    contentId: a.contentId ?? '',
    disposition: a.disposition ?? '',
  }));
  return {
    contentType: content.body.contentType,
    content: raw,
    bodyText,
    htmlBody,
    attachments,
  };
}
