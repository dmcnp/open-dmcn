// SentStore keeps a self-copy of each sent message as the ACTUAL sealed split envelope
// (header + body), stored in the owner-only personal store — not a bespoke record. It's
// sealed to us alone, so it never touches the relay STORE path, onion routing, or the
// free-ride guard. Because it IS a normal envelope, the Sent view reads it with the exact
// same machinery as the inbox: decrypt the small header for the list row, decrypt the
// (large) body on open — so attachments, HTML alternatives, and everything else live in
// the body and are lazy-loaded, and the Sent list only ever handles headers.

import { PersonalStore } from './personalStore';
import type { Preview, FullBody } from './mailboxRest';
import type { WorkingKeys } from '../crypto/workingKeys';
import { decryptHeader, decryptBody, type MailboxEntryLike, type MailboxBodyLike, type SplitEnvelope } from '../crypto/split';
import type { MessageHeaderFields } from '../crypto/protobuf';
import { toBase64, fromBase64 } from '../crypto/keys';

// A synthetic hash keys each Sent row, distinct from real mailbox hashes so the two
// sources never collide.
export const SENT_HASH_PREFIX = 'sent:';
export function isSentStoreHash(hash: string): boolean {
  return hash.startsWith(SENT_HASH_PREFIX);
}

// The header entry is listed (small); the body entry is fetched lazily on open (large).
// Their namespaces differ ("sent/" vs "sent-body/") so the Sent list poll never pulls
// the body bytes.
function sentKey(messageIdHex: string): string {
  return 'sent/' + messageIdHex;
}
function sentBodyKey(messageIdHex: string): string {
  return 'sent-body/' + messageIdHex;
}
function midFromKey(key: string): string {
  return key.slice(key.lastIndexOf('/') + 1);
}

// Stored shapes: the envelope's header/body parts with bytes base64-encoded for JSON.
interface StoredRecipient {
  recipientXPub: string;
  ephemeralXPub: string;
  wrappedCek: string;
  cekNonce: string;
  cekTag: string;
}
interface StoredHeader {
  recipients: StoredRecipient[];
  encryptedHeader: string;
  headerNonce: string;
  headerTag: string;
}
interface StoredBody {
  encryptedBody: string;
  bodyNonce: string;
  bodyTag: string;
}

function encodeHeader(env: SplitEnvelope): StoredHeader {
  return {
    recipients: env.recipients.map(r => ({
      recipientXPub: toBase64(r.recipientXPub),
      ephemeralXPub: toBase64(r.ephemeralXPub),
      wrappedCek: toBase64(r.wrappedCek),
      cekNonce: toBase64(r.cekNonce),
      cekTag: toBase64(r.cekTag),
    })),
    encryptedHeader: toBase64(env.encryptedHeader),
    headerNonce: toBase64(env.headerNonce),
    headerTag: toBase64(env.headerTag),
  };
}
function encodeBody(env: SplitEnvelope): StoredBody {
  return {
    encryptedBody: toBase64(env.encryptedBody),
    bodyNonce: toBase64(env.bodyNonce),
    bodyTag: toBase64(env.bodyTag),
  };
}
function toEntry(h: StoredHeader): MailboxEntryLike {
  return {
    recipients: h.recipients.map(r => ({
      recipientXPub: fromBase64(r.recipientXPub),
      ephemeralXPub: fromBase64(r.ephemeralXPub),
      wrappedCek: fromBase64(r.wrappedCek),
      cekNonce: fromBase64(r.cekNonce),
      cekTag: fromBase64(r.cekTag),
    })),
    encryptedHeader: fromBase64(h.encryptedHeader),
    headerNonce: fromBase64(h.headerNonce),
    headerTag: fromBase64(h.headerTag),
  };
}
function toBody(b: StoredBody): MailboxBodyLike {
  return {
    encryptedBody: fromBase64(b.encryptedBody),
    bodyNonce: fromBase64(b.bodyNonce),
    bodyTag: fromBase64(b.bodyTag),
  };
}

// LegacySentEntry is the pre-envelope Sent record: a plain JSON row under the SAME
// "sent/" namespace, written by every version of this client before Sent moved to storing
// the real self-sealed envelope. It carries the composed plaintext directly.
//
// It is still READ here, and read fully. Switching the write format silently orphaned
// every message a user had already sent — the Sent folder simply came back empty, with no
// error, because the new reader could not decrypt these rows and skipped them. Nothing
// needs migrating: the row already holds everything the list and the reader need, so the
// honest fix is to render it. New sends use the envelope format; these age out on their own.
interface LegacySentEntry {
  v: number;
  messageId: string;
  threadId: string;
  sentAt: number;
  subject: string;
  body: string;
  to: string[];
  cc: string[];
  bcc: string[];
}

// isLegacyEntry discriminates on the plaintext `body` string, which the envelope form
// never has (its body is sealed under a separate key).
function isLegacyEntry(v: unknown): v is LegacySentEntry {
  const e = v as Partial<LegacySentEntry> | null;
  return !!e && typeof e === 'object' && typeof e.body === 'string' && typeof e.subject === 'string';
}

// SNIPPET_MAX mirrors the header snippet length so a legacy row's preview line is the
// same length as an envelope-backed one.
const SNIPPET_MAX = 140;

function previewFromLegacy(hash: string, e: LegacySentEntry, selfAddress: string): Preview {
  const to = e.to ?? [];
  const cc = e.cc ?? [];
  return {
    hash,
    messageId: e.messageId ?? '',
    threadId: e.threadId ?? '',
    senderAddress: selfAddress,
    senderPublicKey: '',
    recipientAddress: to[0] ?? cc[0] ?? '',
    to,
    cc,
    bcc: e.bcc ?? [],
    subject: e.subject ?? '',
    snippet: (e.body ?? '').slice(0, SNIPPET_MAX),
    sentAt: Number(e.sentAt ?? 0),
    bodySize: (e.body ?? '').length,
    attachmentCount: 0,
  };
}

function toHexBytes(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

// previewFromHeader maps a verified header to the shared Preview shape the list/reader
// render — identical to how the mailbox builds previews from its headers.
function previewFromHeader(hash: string, h: MessageHeaderFields): Preview {
  return {
    hash,
    messageId: toHexBytes(h.messageId),
    threadId: toHexBytes(h.threadId),
    senderAddress: h.senderAddress,
    senderPublicKey: toHexBytes(h.senderPublicKey),
    recipientAddress: h.recipientAddress,
    to: h.to ?? [],
    cc: h.cc ?? [],
    bcc: h.bcc ?? [],
    subject: h.subject,
    snippet: h.snippet,
    sentAt: Number(h.sentAt),
    bodySize: Number(h.bodySize),
    attachmentCount: h.attachmentCount,
  };
}

type CachedSent =
  | { kind: 'envelope'; entry: MailboxEntryLike; header: MessageHeaderFields }
  | { kind: 'legacy'; body: string };

export class SentStore {
  private store: PersonalStore;
  private keys: WorkingKeys;
  // hash → what fetchFull needs to open this message: a verified header + entry for the
  // envelope form, or the already-plaintext body for a legacy row.
  private cache = new Map<string, CachedSent>();

  constructor(keys: WorkingKeys) {
    this.store = new PersonalStore(keys);
    this.keys = keys;
  }

  // putEnvelope stores a self-sealed split envelope as a listed header entry plus a lazy
  // body entry.
  async putEnvelope(messageIdHex: string, env: SplitEnvelope): Promise<void> {
    await this.store.put(sentKey(messageIdHex), encodeHeader(env));
    await this.store.put(sentBodyKey(messageIdHex), encodeBody(env));
  }

  // listPreviews turns every stored Sent row into an inbox-style Preview and caches what
  // fetchFull will need. Two row shapes coexist under "sent/": the current self-sealed
  // envelope, and the legacy plaintext record written before the format changed. Both are
  // listed — dropping the legacy ones is what emptied people's Sent folders.
  //
  // A row that is neither (corrupt, or written by something else) is skipped rather than
  // failing the whole list.
  async listPreviews(): Promise<Preview[]> {
    const entries = await this.store.list<StoredHeader | LegacySentEntry>('sent/');
    const previews: Preview[] = [];
    const next = new Map<string, CachedSent>();
    for (const e of entries) {
      const hash = SENT_HASH_PREFIX + midFromKey(e.key);
      if (isLegacyEntry(e.value)) {
        next.set(hash, { kind: 'legacy', body: e.value.body });
        previews.push(previewFromLegacy(hash, e.value, this.keys.address));
        continue;
      }
      try {
        const entry = toEntry(e.value as StoredHeader);
        const header = await decryptHeader(entry, this.keys.x25519Derive, this.keys.x25519Public);
        next.set(hash, { kind: 'envelope', entry, header });
        previews.push(previewFromHeader(hash, header));
      } catch {
        // Neither shape — skip this row, keep the rest of the folder.
      }
    }
    this.cache = next;
    previews.sort((a, b) => b.sentAt - a.sentAt);
    return previews;
  }

  // fetchFull decrypts a Sent message's body on open (attachments + HTML alternatives),
  // in the same shape the inbox reader consumes.
  async fetchFull(hash: string): Promise<FullBody> {
    const cached = this.cache.get(hash);
    if (!cached) throw new Error('no cached header for this sent message');
    // A legacy row already holds its plaintext; there is no separate body entry to fetch.
    // It predates attachments and HTML in Sent, so both are legitimately empty.
    if (cached.kind === 'legacy') return { bodyText: cached.body, attachments: [] };
    const mid = hash.startsWith(SENT_HASH_PREFIX) ? hash.slice(SENT_HASH_PREFIX.length) : hash;
    const b = await this.store.get<StoredBody>(sentBodyKey(mid));
    if (!b) throw new Error('sent body not found');
    const content = await decryptBody(cached.entry, toBody(b.value), cached.header, this.keys.x25519Derive, this.keys.x25519Public);
    return { bodyText: content.bodyText, htmlBody: content.htmlBody, attachments: content.attachments };
  }

  async delete(messageIdHex: string): Promise<void> {
    await this.store.delete(sentKey(messageIdHex));
    await this.store.delete(sentBodyKey(messageIdHex));
  }
}
