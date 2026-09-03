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
import { toBase64, fromBase64, toHex } from '../crypto/keys';

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


// previewFromHeader maps a verified header to the shared Preview shape the list/reader
// render — identical to how the mailbox builds previews from its headers.
function previewFromHeader(hash: string, h: MessageHeaderFields): Preview {
  return {
    hash,
    messageId: toHex(h.messageId),
    threadId: toHex(h.threadId),
    senderAddress: h.senderAddress,
    senderPublicKey: toHex(h.senderPublicKey),
    recipientAddress: h.recipientAddress,
    to: h.to ?? [],
    cc: h.cc ?? [],
    bcc: h.bcc ?? [],
    subject: h.subject,
    snippet: h.snippet,
    senderDisplay: h.senderDisplay ?? '',
    sentAt: Number(h.sentAt),
    bodySize: Number(h.bodySize),
    attachmentCount: h.attachmentCount,
  };
}

export class SentStore {
  private store: PersonalStore;
  private keys: WorkingKeys;
  // hash → verified header + entry, populated by listPreviews so fetchFull can decrypt
  // the body on open without re-listing.
  private cache = new Map<string, { entry: MailboxEntryLike; header: MessageHeaderFields }>();

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

  // listPreviews decrypts every stored header into an inbox-style Preview and caches the
  // header + entry for a later fetchFull. Entries it can't read are skipped rather than
  // failing the whole list.
  //
  // That includes rows written before Sent moved to storing the self-sealed envelope. A
  // reader for them existed briefly and was dropped deliberately: no deployment holds such
  // rows — the hosted fleet's mail was cleared when the format changed, and the open release
  // predates the old format entirely — so it was carrying a migration path for data that does
  // not exist anywhere. If that ever stops being true, rendering them is the fix (the row
  // already holds everything the list and reader need); silently skipping them is not.
  async listPreviews(): Promise<Preview[]> {
    const entries = await this.store.list<StoredHeader>('sent/');
    const previews: Preview[] = [];
    const next = new Map<string, { entry: MailboxEntryLike; header: MessageHeaderFields }>();
    for (const e of entries) {
      try {
        const entry = toEntry(e.value);
        const header = await decryptHeader(entry, this.keys.x25519Derive, this.keys.x25519Public);
        const hash = SENT_HASH_PREFIX + midFromKey(e.key);
        next.set(hash, { entry, header });
        previews.push(previewFromHeader(hash, header));
      } catch {
        // Unreadable entry (foreign/legacy) — skip it.
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
