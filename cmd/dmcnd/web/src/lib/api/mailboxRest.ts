// MailboxSync drives the durable mailbox over plain REST (a two-phase
// challenge/complete the caller polls). It signs each relay challenge with the
// in-browser key, decrypts + verifies header previews, and fetches/verifies
// bodies on open. The private key never leaves the browser. Replaces the former
// WebSocket MailboxClient; the decrypt/cache logic is unchanged.

import { signWithKey } from '../crypto/sign';
import { postJSON } from './client';
import { decodeMailboxEntry, decodeMailboxBody, type MessageHeaderFields } from '../crypto/protobuf';
import { decryptHeader, decryptBody, type MailboxEntryLike, type MailboxBodyLike, type DecryptedAttachment } from '../crypto/split';
import { fromBase64, toBase64 } from '../crypto/keys';
import type { WorkingKeys } from '../crypto/workingKeys';

export interface FullBody {
  bodyText: string;
  // The text/html rendering when the message carries one (multipart/alternative
  // analog). Absent for plain-only mail. The reader renders it sanitized + sandboxed.
  htmlBody?: string;
  attachments: DecryptedAttachment[];
}

export interface Preview {
  hash: string;
  // Hex of the header messageId. Shared across every copy of one compose, so the
  // Sent view groups a multi-recipient send into a single row.
  messageId: string;
  // Hex of the header threadId — lets a reply continue the original thread.
  // All-zero/empty for pre-feature messages.
  threadId: string;
  senderAddress: string;
  // Hex of the sender's ed25519 public key from the signature-verified header
  // (decryptHeader throws on a bad signature). Used to anchor sender trust against
  // the directory + allowlist (crypto/senderTrust.ts) without re-verifying.
  senderPublicKey: string;
  recipientAddress: string;
  // Full recipient lists from the signed header (empty for pre-feature messages).
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  snippet: string;
  sentAt: number;
  bodySize: number;
  attachmentCount: number;
}

function toHex(b: Uint8Array | undefined): string {
  if (!b) return '';
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

interface CachedEntry {
  entry: MailboxEntryLike;
  header: MessageHeaderFields;
}

interface ChallengeResp { correlation_id: string; nonce: string }
interface ListResp { entries: Array<{ hash: string; entry: string }>; next_cursor: string }
interface BodyResp { hash: string; body: string }

// postAuthed issues a JSON POST with an explicit bearer token, bypassing session
// renewal — used only for the ephemeral pairing session, which is short-lived and
// isolated from the main session's global token.
async function postAuthed<T>(token: string, path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

export class MailboxSync {
  private keys: WorkingKeys;
  private cache = new Map<string, CachedEntry>(); // hash → entry + verified header
  private onPreviews: (p: Preview[]) => void;
  // Signature of the previews last emitted. Previews are immutable per hash, so the
  // set of hashes fully identifies the inbox state; skipping onPreviews when it is
  // unchanged keeps a no-op poll from churning `messages` identity (which would
  // re-render — and flicker — an open message every interval).
  private lastPreviewSig = '';
  // When set, requests use this explicit token directly (pairing). When absent,
  // they go through the global session, which transparently renews on expiry.
  private explicitToken?: string;

  // Errors surface via the returned promises (list/fetchFull/deleteMessage reject),
  // so callers handle them at the call site — no separate error channel needed.
  constructor(keys: WorkingKeys, onPreviews: (p: Preview[]) => void, explicitToken?: string) {
    this.keys = keys;
    this.onPreviews = onPreviews;
    this.explicitToken = explicitToken;
  }

  // No persistent connection to tear down; kept for drop-in compatibility.
  close() {}

  private post<T>(path: string, body: unknown): Promise<T> {
    return this.explicitToken !== undefined
      ? postAuthed<T>(this.explicitToken, path, body)
      : postJSON<T>(path, body);
  }

  private async signNonce(nonceB64: string): Promise<string> {
    return toBase64(await signWithKey(this.keys.ed25519Sign, fromBase64(nonceB64)));
  }

  private async challenge(req: { op: 'list' | 'body' | 'delete'; cursor?: string; hash?: string }): Promise<ChallengeResp> {
    return this.post<ChallengeResp>('/api/v1/mailbox/challenge', req);
  }

  private async complete<T>(correlationId: string, nonceB64: string): Promise<T> {
    const signature = await this.signNonce(nonceB64);
    return this.post<T>('/api/v1/mailbox/complete', { correlation_id: correlationId, signature });
  }

  // list pulls every page of header previews, rebuilds the preview cache (pruning
  // anything no longer present), and emits the sorted previews.
  async list(): Promise<Preview[]> {
    const seen = new Set<string>();
    let cursor = '';
    do {
      const ch = await this.challenge({ op: 'list', cursor });
      const res = await this.complete<ListResp>(ch.correlation_id, ch.nonce);
      for (const e of res.entries) {
        try {
          const entryProto = (await decodeMailboxEntry(fromBase64(e.entry))) as unknown as MailboxEntryLike;
          const header = await decryptHeader(entryProto, this.keys.x25519Derive, this.keys.x25519Public);
          this.cache.set(e.hash, { entry: entryProto, header });
          seen.add(e.hash);
        } catch (err) {
          console.error('preview decrypt failed for', e.hash, err);
        }
      }
      cursor = res.next_cursor || '';
    } while (cursor.length > 0);

    // Drop cached entries that are no longer in the mailbox (deleted here or on
    // another device).
    for (const h of [...this.cache.keys()]) if (!seen.has(h)) this.cache.delete(h);

    const previews = this.previews();
    const sig = previews.map(p => p.hash).join('|');
    if (sig !== this.lastPreviewSig) {
      this.lastPreviewSig = sig;
      this.onPreviews(previews);
    }
    return previews;
  }

  // fetchBody fetches + verifies a message body on open; resolves with the text.
  fetchBody(hash: string): Promise<string> {
    return this.fetchFull(hash).then(f => f.bodyText);
  }

  // fetchFull fetches + verifies a message body and returns its text AND any
  // decrypted attachments (used by device pairing's control messages).
  async fetchFull(hash: string): Promise<FullBody> {
    const cached = this.cache.get(hash);
    if (!cached) throw new Error('no cached header for this message');
    const ch = await this.challenge({ op: 'body', hash });
    const res = await this.complete<BodyResp>(ch.correlation_id, ch.nonce);
    const bodyProto = (await decodeMailboxBody(fromBase64(res.body))) as unknown as MailboxBodyLike;
    const content = await decryptBody(cached.entry, bodyProto, cached.header, this.keys.x25519Derive, this.keys.x25519Public);
    return { bodyText: content.bodyText, htmlBody: content.htmlBody, attachments: content.attachments };
  }

  // deleteMessage removes a message from the mailbox (hold-until-deleted) and
  // re-emits previews.
  async deleteMessage(hash: string): Promise<void> {
    const ch = await this.challenge({ op: 'delete', hash });
    await this.complete<{ hash: string }>(ch.correlation_id, ch.nonce);
    this.cache.delete(hash);
    const previews = this.previews();
    this.lastPreviewSig = previews.map(p => p.hash).join('|');
    this.onPreviews(previews);
  }

  private previews(): Preview[] {
    const previews: Preview[] = [];
    for (const [hash, c] of this.cache) {
      previews.push({
        hash,
        messageId: toHex(c.header.messageId),
        threadId: toHex(c.header.threadId),
        senderAddress: c.header.senderAddress,
        senderPublicKey: toHex(c.header.senderPublicKey),
        recipientAddress: c.header.recipientAddress,
        to: c.header.to ?? [],
        cc: c.header.cc ?? [],
        bcc: c.header.bcc ?? [],
        subject: c.header.subject,
        snippet: c.header.snippet,
        sentAt: Number(c.header.sentAt),
        bodySize: Number(c.header.bodySize),
        attachmentCount: c.header.attachmentCount,
      });
    }
    previews.sort((a, b) => b.sentAt - a.sentAt);
    return previews;
  }
}
