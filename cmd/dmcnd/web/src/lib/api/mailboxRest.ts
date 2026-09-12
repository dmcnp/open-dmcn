// MailboxSync drives the durable mailbox over plain REST (a two-phase
// challenge/complete the caller polls). It signs each relay challenge with the
// in-browser key, decrypts + verifies header previews, and fetches/verifies
// bodies on open. The private key never leaves the browser. Replaces the former
// WebSocket MailboxClient; the decrypt/cache logic is unchanged.

import { signWithKey } from '../crypto/sign';
import { postJSONAs } from './client';
import { decodeMailboxEntry, decodeMailboxBody, type MessageHeaderFields } from '../crypto/protobuf';
import { decryptHeader, decryptBody, type MailboxEntryLike, type MailboxBodyLike, type DecryptedAttachment } from '../crypto/split';
import { fromBase64, toBase64, toHex } from '../crypto/keys';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { AccountIdentity } from '../deployment';

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
  // Hex of the header threadId — lets a reply continue the original thread (see
  // ComposeDialog.handleSend). All-zero/empty for pre-feature messages.
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
  // Human-readable sender name from the signed header ('' when none). Rendered only
  // alongside senderAddress — see trust/displayName.ts for why.
  senderDisplay: string;
  sentAt: number;
  bodySize: number;
  attachmentCount: number;
  // The account's OTHER address this copy was sealed to, when it was: an isolated alias's mail
  // is filed in this one mailbox by the home relay, still sealed to the alias's own key, and
  // this is how the reader says which address the sender wrote to. Unset for the account's
  // own key (which a shared alias also uses).
  deliveredTo?: string;
}

// A header field the bundle may leave unset renders as an empty id.
const hexOrEmpty = (b: Uint8Array | undefined): string => (b ? toHex(b) : '');

interface CachedEntry {
  entry: MailboxEntryLike;
  header: MessageHeaderFields;
  // The keys this copy was sealed to — the body opens with the same ones.
  keys: WorkingKeys;
  deliveredTo?: string;
}

// keyringFor lays out the keys a mailbox may hold copies sealed to: the account's own first,
// then each isolated identity's, by the hex of the X25519 key a recipient record names.
// Returns the decrypt ring AND, from the same single identities() call, when each retired address
// was retired. A retired address keeps its key in the ring — that is what keeps the mail it
// already received readable — so the two have to travel together.
async function keyringFor(keys: WorkingKeys, identities?: () => Promise<AccountIdentity[]>): Promise<{
  ring: Map<string, { keys: WorkingKeys; address?: string }>;
  retired: Map<string, number>;
}> {
  const ring = new Map<string, { keys: WorkingKeys; address?: string }>();
  const retired = new Map<string, number>();
  ring.set(toHex(keys.x25519Public), { keys });
  if (!identities) return { ring, retired };
  let list: AccountIdentity[] = [];
  try {
    list = await identities();
  } catch (err) {
    // The account's own mail still opens; only derived-key copies wait for the next poll.
    console.warn('identities unavailable; opening with the account key only', err);
  }
  for (const id of list) {
    const hex = toHex(id.keys.x25519Public);
    if (!ring.has(hex)) ring.set(hex, { keys: id.keys, address: id.address });
    if (id.retiredAt) retired.set(id.address.toLowerCase(), id.retiredAt);
  }
  return { ring, retired };
}

// arrivedAfterRetirement decides whether one message is a post-retirement arrival at a retired
// address — the only thing the backstop in previews() discards.
//
// Pure and exported because the boundary is the whole point and is easy to get backwards: mail
// that arrived BEFORE the address was retired is ordinary history and must survive, which is also
// why the sealed alias list is MARKED rather than emptied. Only what a sender holding a cached
// record managed to deliver afterwards is dropped.
export function arrivedAfterRetirement(
  address: string | undefined,
  sentAt: number,
  retired: Map<string, number>,
): boolean {
  if (retired.size === 0 || !address) return false;
  const at = retired.get(address.toLowerCase());
  return at !== undefined && sentAt > at;
}

// sealedToOurs finds which of our keys a copy was sealed to.
function sealedToOurs(entry: MailboxEntryLike, ring: Map<string, { keys: WorkingKeys; address?: string }>): { keys: WorkingKeys; address?: string } | undefined {
  for (const r of entry.recipients) {
    const hit = ring.get(toHex(new Uint8Array(r.recipientXPub)));
    if (hit) return hit;
  }
  return undefined;
}

interface ChallengeResp { correlation_id: string; nonce: string }
interface ListResp { entries: Array<{ hash: string; entry: string }>; next_cursor: string }
interface BodyResp { hash: string; body: string }

export class MailboxSync {
  private keys: WorkingKeys;
  private cache = new Map<string, CachedEntry>(); // hash → entry + verified header
  private onPreviews: (p: Preview[]) => void;
  // Signature of the previews last emitted. Previews are immutable per hash, so the
  // set of hashes fully identifies the inbox state; skipping onPreviews when it is
  // unchanged keeps a no-op poll from churning `messages` identity (which would
  // re-render — and flicker — an open message every interval).
  private lastPreviewSig = '';
  // When set, requests use this explicit token directly — the pairing session, or a
  // background account being counted by the switcher. When absent, they go through
  // the global session, which transparently renews on expiry.
  private explicitToken?: string;
  // The account's other identities (deployment.identities), consulted once per list so a copy
  // sealed to a derived key opens with that key. Absent ⇒ the account key alone.
  private identities?: () => Promise<AccountIdentity[]>;
  // When each retired address was retired, refreshed on every list. Empty until the first poll.
  private retired = new Map<string, number>();

  // Errors surface via the returned promises (list/fetchFull/deleteMessage reject),
  // so callers handle them at the call site — no separate error channel needed.
  constructor(keys: WorkingKeys, onPreviews: (p: Preview[]) => void, explicitToken?: string, identities?: () => Promise<AccountIdentity[]>) {
    this.keys = keys;
    this.onPreviews = onPreviews;
    this.explicitToken = explicitToken;
    this.identities = identities;
  }

  // No persistent connection to tear down; kept for drop-in compatibility.
  close() {}

  private post<T>(path: string, body: unknown): Promise<T> {
    return postJSONAs<T>(this.explicitToken, path, body);
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
    const { ring, retired } = await keyringFor(this.keys, this.identities);
    this.retired = retired;
    let cursor = '';
    do {
      const ch = await this.challenge({ op: 'list', cursor });
      const res = await this.complete<ListResp>(ch.correlation_id, ch.nonce);
      for (const e of res.entries) {
        seen.add(e.hash);
        // The hash IS the envelope digest, so an entry is immutable under it: a
        // header already decrypted and signature-verified this session never needs
        // redoing. That keeps a poll cheap on a large mailbox — and is what makes
        // counting another account's unread mail in the background affordable.
        if (this.cache.has(e.hash)) continue;
        try {
          const entryProto = (await decodeMailboxEntry(fromBase64(e.entry))) as unknown as MailboxEntryLike;
          const ours = sealedToOurs(entryProto, ring);
          if (!ours) throw new Error('sealed to none of this account\'s keys');
          const header = await decryptHeader(entryProto, ours.keys.x25519Derive, ours.keys.x25519Public);
          this.cache.set(e.hash, { entry: entryProto, header, keys: ours.keys, deliveredTo: ours.address });
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
    const content = await decryptBody(cached.entry, bodyProto, cached.header, cached.keys.x25519Derive, cached.keys.x25519Public);
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
    // The backstop for a retired address. Retirement stops the record resolving, so no sender who
    // looks it up can reach it — but one holding a CACHED record still can, because STORE keys on
    // the recipient key and never resolves. Those arrivals are suppressed here and deleted
    // best-effort, so "stopped" means stopped from the owner's side too. Strictly bounded by
    // retiredAt: without that clause this would eat the mail the address legitimately received
    // before it was retired, which is exactly what the sealed list is marked (not emptied) to keep.
    const retired = this.retired;
    for (const [hash, c] of this.cache) {
      if (arrivedAfterRetirement(c.deliveredTo ?? c.header.recipientAddress, Number(c.header.sentAt), retired)) {
        this.cache.delete(hash);
        void this.deleteMessage(hash).catch(() => { /* it stays on the relay; it is still hidden here */ });
        continue;
      }
      previews.push({
        hash,
        messageId: hexOrEmpty(c.header.messageId),
        threadId: hexOrEmpty(c.header.threadId),
        senderAddress: c.header.senderAddress,
        senderPublicKey: hexOrEmpty(c.header.senderPublicKey),
        recipientAddress: c.header.recipientAddress,
        to: c.header.to ?? [],
        cc: c.header.cc ?? [],
        bcc: c.header.bcc ?? [],
        subject: c.header.subject,
        snippet: c.header.snippet,
        senderDisplay: c.header.senderDisplay ?? '',
        sentAt: Number(c.header.sentAt),
        bodySize: Number(c.header.bodySize),
        attachmentCount: c.header.attachmentCount,
        deliveredTo: c.deliveredTo,
      });
    }
    previews.sort((a, b) => b.sentAt - a.sentAt);
    return previews;
  }
}
