// MailboxSync drives the durable mailbox over plain REST (a two-phase
// challenge/complete the caller polls). It signs each relay challenge with the
// in-browser key, decrypts + verifies header previews, and fetches/verifies
// bodies on open. The private key never leaves the browser. Replaces the former
// WebSocket MailboxClient.
//
// The rows it draws are also kept on this device, sealed (previewCache.ts), so an unlock shows the
// list at once and a poll only opens what is new. Those rows are only ever drawn: opening a message
// fetches its header afresh from the listing and verifies it before any body is decrypted.

import { postJSONAs } from './client';
import { asDecryptOnly, retiredKeys } from '../crypto/retiredKeys';
import { mailboxProof } from './mailboxProof';
import { decodeMailboxEntry, decodeMailboxBody, type MessageHeaderFields } from '../crypto/protobuf';
import { decryptHeader, decryptBody, type MailboxEntryLike, type MailboxBodyLike, type DecryptedAttachment } from '../crypto/split';
import { fromBase64, toHex } from '../crypto/keys';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { AccountIdentity } from '../deployment';
import { PreviewCache } from './previewCache';
import type { ChangeEvent, FeedPosition } from '../sync/changes';

export interface FullBody {
  bodyText: string;
  // The text/html rendering when the message carries one (multipart/alternative
  // analog). Absent for plain-only mail. The reader renders it sanitized + sandboxed.
  htmlBody?: string;
  attachments: DecryptedAttachment[];
  // Hex of the header's reply_to_id ('' when it names nothing), from the header this open
  // verified. The list row does not carry it; the export needs it to thread replies.
  replyToId?: string;
  // The row as the header this open verified says it is. A row drawn from this device is
  // corrected to match before this resolves, so a caller holding an older copy of the row (the
  // export, which keeps the list it started from) writes what the relay's signed header says.
  row?: Preview;
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

// reply_to_id, where an all-zero id means "not a reply" just as an absent one does.
export const replyIdHex = (b: Uint8Array | undefined): string => (b && b.some(x => x !== 0) ? toHex(b) : '');

interface OpenedEntry {
  entry: MailboxEntryLike;
  header: MessageHeaderFields;
  // The keys this copy was sealed to — the body opens with the same ones.
  keys: WorkingKeys;
}

interface CachedEntry {
  // The row, from a header verified this session or read back from this device.
  preview: Preview;
  // The entry as the relay listed it this session (base64 wire bytes). Absent for a row read back
  // from this device until the first listing lands.
  raw?: string;
  // The entry opened: decoded, its header decrypted and signature-verified. Present for what this
  // session opened itself; a row from this device is opened when someone opens the message.
  opened?: OpenedEntry;
}

// previewOf maps a verified header to the row the list draws.
function previewOf(hash: string, h: MessageHeaderFields, deliveredTo?: string): Preview {
  return {
    hash,
    messageId: hexOrEmpty(h.messageId),
    threadId: hexOrEmpty(h.threadId),
    senderAddress: h.senderAddress,
    senderPublicKey: hexOrEmpty(h.senderPublicKey),
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
    deliveredTo,
  };
}

// Two rows for one hash say the same thing. Only a row read back from this device can differ from
// the header the relay serves now, and then the relay's verified header is what the list shows.
const sameRow = (a: Preview, b: Preview) => JSON.stringify(a) === JSON.stringify(b);

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

  // Generations this account used to hold. A rotation re-keys the mailbox without re-sealing what
  // is in it — the relay cannot, since it cannot read it — so mail that arrived before the change
  // opens only with the key it arrived under. Without these, rotating would look to the owner like
  // their history had been deleted.
  for (const r of await retiredKeys(keys.address)) {
    const hex = toHex(r.x25519Public);
    if (!ring.has(hex)) ring.set(hex, { keys: { ...keys, ...asDecryptOnly(keys.address, r) } });
  }

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
// Entries asked for per list page. The relay caps a page by bytes as well, so this is an upper
// bound, set to make a large mailbox a few round trips rather than hundreds.
const LIST_PAGE = 500;
interface ListResp { entries: Array<{ hash: string; entry: string }>; next_cursor: string }
interface BodyResp { hash: string; body: string }

export class MailboxSync {
  private keys: WorkingKeys;
  private cache = new Map<string, CachedEntry>(); // hash → row, and the entry once listed/opened
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
  // The decrypt ring from the latest listing, for opening an entry that was listed but not opened.
  private ring: Map<string, { keys: WorkingKeys; address?: string }> | null = null;
  // This account's rows on this device (null: none for these keys); loaded once, on first list.
  private rows: PreviewCache | null = null;
  private restoring?: Promise<void>;
  // Whether a listing has completed this session: until one has, a row without a listed entry may
  // simply not have been listed yet.
  private listed = false;

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



  private async challenge(req: { op: 'list' | 'body' | 'delete'; cursor?: string; hash?: string; limit?: number }): Promise<ChallengeResp> {
    return this.post<ChallengeResp>('/api/v1/mailbox/challenge', req);
  }

  private async complete<T>(correlationId: string, nonceB64: string): Promise<T> {
    return this.post<T>('/api/v1/mailbox/complete', {
      correlation_id: correlationId,
      ...(await mailboxProof(this.keys, nonceB64)),
    });
  }

  // restore draws the rows this device kept from an earlier session, before anything is fetched.
  // Once per instance; a failure only means starting from the relay, as before. Public as
  // showKept for a caller that will bring the rows up to date some other way than listing (the
  // change feed, useSync.ts).
  showKept(): Promise<void> {
    return this.restore();
  }

  private restore(): Promise<void> {
    return (this.restoring ??= (async () => {
      try {
        this.rows = await PreviewCache.open(this.keys, 'inbox');
        if (!this.rows) return;
        const kept = await this.rows.load();
        for (const [hash, row] of kept.rows) {
          if (!this.cache.has(hash)) this.cache.set(hash, { preview: row.preview });
        }
        // Read once, with the rows: from here this instance's position describes this instance's
        // rows, whatever another tab writes to the shared store afterwards.
        this.position ??= kept.position;
        if (this.cache.size > 0) this.emit();
      } catch (err) {
        this.rows = null;
        console.warn('list cache unavailable; listing from the relay', err);
      }
    })());
  }

  // ensureRing builds the decrypt ring when nothing has listed yet this session.
  private async ensureRing(): Promise<void> {
    if (this.ring) return;
    const { ring, retired } = await keyringFor(this.keys, this.identities);
    this.ring = ring;
    this.retired = retired;
  }

  // Where the change feed stands for these rows. Kept with the rows on this device when they
  // are kept (previewCache.ts), else only for this session.
  private position: FeedPosition | null = null;

  /** The change-feed position these rows are at, or null when a full listing is needed first. */
  async feedPosition(): Promise<FeedPosition | null> {
    await this.restore();
    return this.position;
  }

  /** Record the position these rows are now at, and (as the writer) keep both on this device. */
  async setFeedPosition(p: FeedPosition): Promise<void> {
    await this.restore();
    this.position = p;
    if (this.writer && this.rows) await this.rows.save(this.snapshot(), p);
  }

  // Whether this instance keeps the list on this device. Several tabs of one account share the
  // store, and each holds its own rows at its own position; if they all wrote, the store could
  // end up with one tab's rows beside another's position, and an unlock would then skip events.
  // So exactly one writes — the tab holding the account's lock (useMessages) — and the others
  // only read at start. Off by default: a background reader (the unread counter) never writes.
  private writer = false;

  /**
   * Become the one that keeps this list on this device. What is stored may be another tab's, so
   * the first write replaces all of it with this instance's rows and position.
   */
  async becomeWriter(): Promise<void> {
    await this.restore();
    this.writer = true;
    if (!this.rows) return;
    this.rows.rewriteAll();
    await this.rows.save(this.snapshot(), this.position);
  }

  private snapshot(): Map<string, { preview: Preview; raw?: string }> {
    const rows = new Map<string, { preview: Preview; raw?: string }>();
    for (const [hash, c] of this.cache) rows.set(hash, { preview: c.preview, raw: c.raw });
    return rows;
  }

  /** Resolves once every write of rows to this device queued so far has landed. */
  settled(): Promise<void> {
    return this.rows ? this.rows.settled() : Promise.resolve();
  }

  /** Forget the decrypt ring, so the next open rebuilds it (the account's aliases changed). */
  invalidateRing(): void {
    this.ring = null;
  }

  /**
   * Apply change-feed events to the list, and write the result to this device before resolving —
   * the caller advances its feed position only after that, so a crash replays events rather than
   * losing them. Replay is harmless: a message already held is not added twice, one already gone
   * is not deleted twice.
   *
   * A stored message arrives with its list entry, which is opened and verified exactly as a
   * listing's would be. One deleted since it was stored arrives without, and its deletion follows.
   */
  async applyEvents(events: ChangeEvent[]): Promise<void> {
    await this.restore();
    let changed = false;
    for (const e of events) {
      if (!e.hash) continue;
      if (e.kind === 'mail_deleted') {
        if (this.cache.delete(e.hash)) changed = true;
        continue;
      }
      if (e.kind !== 'mail_stored' || !e.entry) continue;
      const had = this.cache.get(e.hash);
      if (had) {
        if (!had.raw) { had.raw = e.entry; changed = true; }
        continue;
      }
      try {
        await this.ensureRing();
        const o = await this.openEntry(e.entry);
        this.cache.set(e.hash, {
          preview: previewOf(e.hash, o.header, o.address),
          raw: e.entry,
          opened: { entry: o.entry, header: o.header, keys: o.keys },
        });
        changed = true;
      } catch (err) {
        console.error('preview decrypt failed for', e.hash, err);
      }
    }
    if (!changed) return;
    this.emit();
    if (this.writer && this.rows) await this.rows.save(this.snapshot(), this.position);
  }

  // openEntry decodes a listed entry, finds which of our keys it was sealed to, and decrypts and
  // verifies its header.
  private async openEntry(raw: string): Promise<OpenedEntry & { address?: string }> {
    if (!this.ring) throw new Error('mailbox not listed yet');
    const entry = (await decodeMailboxEntry(fromBase64(raw))) as unknown as MailboxEntryLike;
    const ours = sealedToOurs(entry, this.ring);
    if (!ours) throw new Error('sealed to none of this account\'s keys');
    const header = await decryptHeader(entry, ours.keys.x25519Derive, ours.keys.x25519Public);
    return { entry, header, keys: ours.keys, address: ours.address };
  }

  // list pulls every page of header previews, rebuilds the preview cache (pruning
  // anything no longer present), and emits the sorted previews.
  async list(): Promise<Preview[]> {
    await this.restore();
    const seen = new Set<string>();
    const { ring, retired } = await keyringFor(this.keys, this.identities);
    this.ring = ring;
    this.retired = retired;
    let cursor = '';
    let firstPage = true;
    do {
      const ch = await this.challenge({ op: 'list', cursor, limit: LIST_PAGE });
      const res = await this.complete<ListResp>(ch.correlation_id, ch.nonce);
      for (const e of res.entries) {
        seen.add(e.hash);
        // The hash IS the envelope digest, so an entry is immutable under it: a row already
        // drawn — verified this session, or in an earlier one and kept on this device — never
        // needs opening again to be listed. That keeps a poll cheap on a large mailbox, and is
        // what makes counting another account's unread mail in the background affordable.
        const had = this.cache.get(e.hash);
        if (had) { had.raw = e.entry; continue; }
        try {
          const o = await this.openEntry(e.entry);
          this.cache.set(e.hash, {
            preview: previewOf(e.hash, o.header, o.address),
            raw: e.entry,
            opened: { entry: o.entry, header: o.header, keys: o.keys },
          });
        } catch (err) {
          console.error('preview decrypt failed for', e.hash, err);
        }
      }
      cursor = res.next_cursor || '';
      // A relay that lists newest first has just handed over the mail most likely to be missing
      // from the list: draw it now rather than after the whole mailbox. Nothing is pruned until
      // the last page, so an early draw only ever adds rows. (An older relay lists oldest
      // first; drawing early there is merely less useful, never wrong.)
      if (firstPage && cursor.length > 0) this.emit();
      firstPage = false;
    } while (cursor.length > 0);

    // Drop entries that are no longer in the mailbox (deleted here or on another device), and
    // rows kept on this device for mail that has gone since.
    for (const h of [...this.cache.keys()]) if (!seen.has(h)) this.cache.delete(h);

    this.listed = true;
    const previews = this.emit();
    this.persist();
    return previews;
  }

  // emit hands the previews to the subscriber when the set of messages changed (or when told to:
  // a row was corrected in place), and returns them.
  private emit(force = false): Preview[] {
    const previews = this.previews();
    const sig = previews.map(p => p.hash).join('|');
    if (force || sig !== this.lastPreviewSig) {
      this.lastPreviewSig = sig;
      this.onPreviews(previews);
    }
    return previews;
  }

  // persist writes the current rows to this device. Best effort: a failed write costs the next
  // unlock some decrypting, nothing else.
  private persist(): void {
    if (!this.writer || !this.rows) return;
    void this.rows.save(this.snapshot(), this.position).catch(err => console.warn('list cache: could not save', err));
  }

  // fetchBody fetches + verifies a message body on open; resolves with the text.
  fetchBody(hash: string): Promise<string> {
    return this.fetchFull(hash).then(f => f.bodyText);
  }

  // fetchFull fetches + verifies a message body and returns its text AND any
  // decrypted attachments (used by device pairing's control messages).
  //
  // A row read back from this device is not trusted to open anything: the header comes from this
  // session's listing and is verified here, and if it says something other than the row did, the
  // row is corrected to match it.
  async fetchFull(hash: string): Promise<FullBody> {
    await this.restore();
    let cached = this.cache.get(hash);
    if (cached && !cached.raw && this.rows) {
      // Kept on this device beside its row: no listing needed to open it.
      cached.raw = await this.rows.entry(hash);
      if (cached.raw) await this.ensureRing();
    }
    if (!cached?.raw && !this.listed) {
      // Drawn from this device, and the first listing has not landed yet: wait for one.
      await this.list();
      cached = this.cache.get(hash);
    }
    if (!cached?.raw) throw new Error('no cached header for this message');
    if (!cached.opened) {
      const o = await this.openEntry(cached.raw);
      cached.opened = { entry: o.entry, header: o.header, keys: o.keys };
      const verified = previewOf(hash, o.header, o.address);
      if (!sameRow(verified, cached.preview)) {
        cached.preview = verified;
        this.emit(true);
        this.persist();
      }
    }
    const { entry, header, keys } = cached.opened;
    const ch = await this.challenge({ op: 'body', hash });
    const res = await this.complete<BodyResp>(ch.correlation_id, ch.nonce);
    const bodyProto = (await decodeMailboxBody(fromBase64(res.body))) as unknown as MailboxBodyLike;
    const content = await decryptBody(entry, bodyProto, header, keys.x25519Derive, keys.x25519Public);
    return {
      bodyText: content.bodyText, htmlBody: content.htmlBody, attachments: content.attachments,
      replyToId: replyIdHex(header.replyToId), row: cached.preview,
    };
  }

  // deleteMessage removes a message from the mailbox (hold-until-deleted) and
  // re-emits previews.
  async deleteMessage(hash: string): Promise<void> {
    const ch = await this.challenge({ op: 'delete', hash });
    await this.complete<{ hash: string }>(ch.correlation_id, ch.nonce);
    this.cache.delete(hash);
    this.emit();
    this.persist();
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
      if (arrivedAfterRetirement(c.preview.deliveredTo ?? c.preview.recipientAddress, c.preview.sentAt, retired)) {
        this.cache.delete(hash);
        void this.deleteMessage(hash).catch(() => { /* it stays on the relay; it is still hidden here */ });
        continue;
      }
      previews.push(c.preview);
    }
    previews.sort((a, b) => b.sentAt - a.sentAt);
    return previews;
  }
}
