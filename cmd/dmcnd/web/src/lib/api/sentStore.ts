// SentStore keeps a self-copy of each sent message as the ACTUAL sealed split envelope
// (header + body), stored in the owner-only personal store — not a bespoke record. It's
// sealed to us alone, so it never touches the relay STORE path, onion routing, or the
// free-ride guard. Because it IS a normal envelope, the Sent view reads it with the exact
// same machinery as the inbox: decrypt the small header for the list row, decrypt the
// (large) body on open — so attachments, HTML alternatives, and everything else live in
// the body and are lazy-loaded, and the Sent list only ever handles headers.

import { PersonalStore } from './personalStore';
import { replyIdHex, type Preview, type FullBody } from './mailboxRest';
import type { WorkingKeys } from '../crypto/workingKeys';
import { decryptHeader, decryptBody, type MailboxEntryLike, type MailboxBodyLike, type SplitEnvelope } from '../crypto/split';
import { asDecryptOnly, retiredKeys } from '../crypto/retiredKeys';
import { KDF_V1, KDF_V2 } from '../crypto/sealVersion';
import type { MessageHeaderFields } from '../crypto/protobuf';
import { toBase64, fromBase64, toHex } from '../crypto/keys';
import { PreviewCache } from './previewCache';

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
  // The CEK-wrap / AEAD generation this slot was sealed with (sealVersion.ts). It rides on
  // the wire beside the slot and is stored here for the same reason: the reader dispatches
  // on it, and a row that lost it can only be opened by guessing (openStoredHeader).
  kdf?: number;
}
export interface StoredHeader {
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

export function encodeStoredHeader(env: SplitEnvelope): StoredHeader {
  return {
    recipients: env.recipients.map(r => ({
      recipientXPub: toBase64(r.recipientXPub),
      ephemeralXPub: toBase64(r.ephemeralXPub),
      wrappedCek: toBase64(r.wrappedCek),
      cekNonce: toBase64(r.cekNonce),
      cekTag: toBase64(r.cekTag),
      kdf: r.kdf,
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
function toEntry(h: StoredHeader, kdf?: number): MailboxEntryLike {
  return {
    recipients: h.recipients.map(r => ({
      recipientXPub: fromBase64(r.recipientXPub),
      ephemeralXPub: fromBase64(r.ephemeralXPub),
      wrappedCek: fromBase64(r.wrappedCek),
      cekNonce: fromBase64(r.cekNonce),
      cekTag: fromBase64(r.cekTag),
      kdf: kdf ?? r.kdf,
    })),
    encryptedHeader: fromBase64(h.encryptedHeader),
    headerNonce: fromBase64(h.headerNonce),
    headerTag: fromBase64(h.headerTag),
  };
}
// openStoredHeader decrypts a stored Sent header and returns it with the entry it opened
// under, which is what the body decrypt later reads its generation from.
//
// A row that carries no generation was written either by a client that sealed with the
// current generation but did not yet store the field (the hosted client from the field's
// arrival until this store learnt to keep it — every send in that window vanished from Sent
// with an OperationError), or by one that predates the field and sealed with the first.
// Nothing in the row says which, so each generation is tried newest first: two
// authenticated attempts, so a wrong guess fails and never mis-decrypts.
export async function openStoredHeader(
  h: StoredHeader,
  x25519Derive: CryptoKey,
  x25519Pub: Uint8Array
): Promise<{ entry: MailboxEntryLike; header: MessageHeaderFields }> {
  const candidates = h.recipients.every(r => r.kdf !== undefined) ? [undefined] : [KDF_V2, KDF_V1];
  let lastErr: unknown;
  for (const kdf of candidates) {
    const entry = toEntry(h, kdf);
    try {
      return { entry, header: await decryptHeader(entry, x25519Derive, x25519Pub) };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr;
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

// One Sent row: what the list draws, the storage version it was read at, and — once this session
// has listed or opened it — the stored header and the opened entry the body decrypts with.
interface SentRow {
  preview: Preview;
  version: number;
  raw?: StoredHeader;
  opened?: { entry: MailboxEntryLike; header: MessageHeaderFields };
}

const sortedPreviews = (rows: Map<string, SentRow>) =>
  [...rows.values()].map(r => r.preview).sort((a, b) => b.sentAt - a.sentAt);

export class SentStore {
  private store: PersonalStore;
  private keys: WorkingKeys;
  // hash → row, populated by listPreviews (and, before the first listing, from this device) so
  // fetchFull can decrypt the body on open without re-listing.
  private cache = new Map<string, SentRow>();
  // The rows kept on this device (previewCache.ts); loaded once, on first use.
  private rows: PreviewCache | null = null;
  private restoring?: Promise<void>;
  private listed = false;

  constructor(keys: WorkingKeys) {
    this.store = new PersonalStore(keys);
    this.keys = keys;
  }

  /**
   * The keys this account's own copies may be sealed to, current generation first.
   *
   * A Sent entry is sealed to the key that SENT it, and a rotation re-keys the account without
   * re-sealing the mail — so every message sent before a re-key opens only with the generation it
   * was sent under. Without this the Sent folder empties itself the day someone rotates, which is
   * a strange way to find out that the retired key was kept for exactly this.
   *
   * The sweep that re-seals personal storage deliberately skips `sent/`: those entries are mail,
   * one per message, and rewriting the archive is not a sweep. This is what makes that skip safe.
   */
  private async generations(): Promise<Array<Pick<WorkingKeys, 'x25519Derive' | 'x25519Public'>>> {
    return [this.keys, ...(await retiredKeys(this.keys.address)).map(r => asDecryptOnly(this.keys.address, r))];
  }

  /** Open a stored header with whichever generation sealed it. */
  private async openHeader(h: StoredHeader): Promise<{ entry: MailboxEntryLike; header: MessageHeaderFields }> {
    let lastErr: unknown;
    for (const g of await this.generations()) {
      try {
        return await openStoredHeader(h, g.x25519Derive, g.x25519Public);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr;
  }

  /** Open a stored body with whichever generation sealed it. */
  private async openBody(entry: MailboxEntryLike, body: MailboxBodyLike, header: MessageHeaderFields) {
    let lastErr: unknown;
    for (const g of await this.generations()) {
      try {
        return await decryptBody(entry, body, header, g.x25519Derive, g.x25519Public);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr;
  }

  // putEnvelope stores a self-sealed split envelope as a listed header entry plus a lazy
  // body entry.
  async putEnvelope(messageIdHex: string, env: SplitEnvelope): Promise<void> {
    await this.store.put(sentKey(messageIdHex), encodeStoredHeader(env));
    await this.store.put(sentBodyKey(messageIdHex), encodeBody(env));
  }

  // restore reads the rows this device kept from an earlier session. Once; a failure only means
  // starting from the store, as before.
  private restore(): Promise<void> {
    return (this.restoring ??= (async () => {
      try {
        this.rows = await PreviewCache.open(this.keys, 'sent');
        if (!this.rows) return;
        for (const [hash, row] of (await this.rows.load()).rows) {
          if (!this.cache.has(hash)) this.cache.set(hash, { preview: row.preview, version: row.version ?? -1 });
        }
      } catch (err) {
        this.rows = null;
        console.warn('Sent: list cache unavailable; listing from the store', err);
      }
    })());
  }

  private persist(): void {
    if (!this.rows) return;
    const rows = new Map<string, { preview: Preview; version: number }>();
    for (const [hash, r] of this.cache) rows.set(hash, { preview: r.preview, version: r.version });
    void this.rows.save(rows).catch(err => console.warn('Sent: could not save the list cache', err));
  }

  /** The rows this device kept from an earlier session, to draw before the first listing lands. */
  async cachedPreviews(): Promise<Preview[]> {
    await this.restore();
    return sortedPreviews(this.cache);
  }

  // listPreviews decrypts every stored header it has not already opened into an inbox-style
  // Preview. An entry already held at the same storage version — from this session, or kept on
  // this device from an earlier one — is not opened again. Entries it can't read are skipped
  // rather than failing the whole list.
  //
  // That includes rows written before Sent moved to storing the self-sealed envelope. A
  // reader for them existed briefly and was dropped deliberately: no deployment holds such
  // rows — the hosted fleet's mail was cleared when the format changed, and the open release
  // predates the old format entirely — so it was carrying a migration path for data that does
  // not exist anywhere. If that ever stops being true, rendering them is the fix (the row
  // already holds everything the list and reader need); silently skipping them is not.
  async listPreviews(): Promise<Preview[]> {
    await this.restore();
    const entries = await this.store.list<StoredHeader>('sent/');
    const next = new Map<string, SentRow>();
    for (const e of entries) {
      const hash = SENT_HASH_PREFIX + midFromKey(e.key);
      const had = this.cache.get(hash);
      if (had && had.version === e.version) {
        had.raw = e.value;
        next.set(hash, had);
        continue;
      }
      try {
        const opened = await this.openHeader(e.value);
        next.set(hash, { preview: previewFromHeader(hash, opened.header), version: e.version, raw: e.value, opened });
      } catch (err) {
        // Unreadable entry (foreign/legacy) — skip it, but say so: a Sent folder that is
        // silently short of a row it just wrote is undiagnosable from the page.
        console.warn('Sent: skipping an unreadable entry', e.key, err);
      }
    }
    this.cache = next;
    this.listed = true;
    this.persist();
    return sortedPreviews(next);
  }

  // fetchFull decrypts a Sent message's body on open (attachments + HTML alternatives),
  // in the same shape the inbox reader consumes. A row kept on this device opens nothing by
  // itself: the header comes from this session's listing and is opened here.
  async fetchFull(hash: string): Promise<FullBody> {
    await this.restore();
    let row = this.cache.get(hash);
    if (!row?.raw && !this.listed) {
      await this.listPreviews();
      row = this.cache.get(hash);
    }
    if (!row?.raw) throw new Error('no cached header for this sent message');
    if (!row.opened) {
      row.opened = await this.openHeader(row.raw);
      const verified = previewFromHeader(hash, row.opened.header);
      if (JSON.stringify(verified) !== JSON.stringify(row.preview)) {
        row.preview = verified;
        this.persist();
      }
    }
    const mid = hash.startsWith(SENT_HASH_PREFIX) ? hash.slice(SENT_HASH_PREFIX.length) : hash;
    const b = await this.store.get<StoredBody>(sentBodyKey(mid));
    if (!b) throw new Error('sent body not found');
    const content = await this.openBody(row.opened.entry, toBody(b.value), row.opened.header);
    return {
      bodyText: content.bodyText, htmlBody: content.htmlBody, attachments: content.attachments,
      replyToId: replyIdHex(row.opened.header.replyToId), row: row.preview,
    };
  }

  async delete(messageIdHex: string): Promise<void> {
    await this.store.delete(sentKey(messageIdHex));
    await this.store.delete(sentBodyKey(messageIdHex));
    if (this.cache.delete(SENT_HASH_PREFIX + messageIdHex)) this.persist();
  }
}
