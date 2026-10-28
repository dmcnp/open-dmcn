// DraftStore keeps the messages being written, so closing the composer, a crashed tab or a second
// device never costs someone the message they were halfway through.
//
// Drafts live in the owner-only personal store, like Sent: every record is sealed to the owner in
// this browser before it leaves it, so the relay holds ciphertext and the same draft opens on every
// device the account is unlocked on. Three namespaces, for the same reason Sent has two — what a
// list needs must not drag along what only an open draft needs:
//
//   drafts/<id>               the row: who it is to, the subject, a snippet, when it was saved
//   draft-body/<id>           the text (and the editor's HTML), the reply it answers, half-typed fields
//   draft-att/<id>/<attId>    one record per attachment, written once when added
//
// The split is what makes saving every few seconds affordable: a keystroke rewrites the row and the
// body, never the 25 MB of attachments beside them.
//
// Two devices editing one draft is settled by compare-and-swap, never by merging. Each save names
// the versions it last saw, and a save that finds something newer stops before the row is touched
// and reports a DraftConflictError, so the composer can ask which copy to keep.
//
// Beside the relay copy, this device keeps the latest state of each draft it is writing in
// IndexedDB until the relay has it (the 'draft::' records in the 'personal' store) — the cover for
// a dropped network, or a tab closed in the seconds before a save. That copy is NOT encrypted: it
// is the owner's own unsent message on the owner's own device, the same footing as the personal
// store's local fallback, and a deliberate choice rather than an oversight. A temporary session (a
// borrowed computer) keeps none, because nothing of the account is meant to stay behind there.

import { PersonalStore, StorageConflictError } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { AttachmentInput } from '../crypto/split';
import type { ComposeReplyTo } from '../compose';
import { toBase64, fromBase64, toHex, fromHex } from '../crypto/keys';
import { idbDelete, idbEntriesWithPrefix, idbGet, idbPut, idbDeletePrefix, PERSONAL_STORE } from '../crypto/idb';

/** Everything the composer needs to put a draft back the way it was left. */
export interface DraftContent {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  /** Text typed into a recipient field but not yet turned into a chip. */
  pending: { to: string; cc: string; bcc: string };
  showCcBcc: boolean;
  subject: string;
  rich: boolean;
  /** The plain-text body; in rich mode, the text rendering of `html` (snippets are drawn from it). */
  text: string;
  /** The editor's HTML with inline images as cid: references; '' in plain mode. */
  html: string;
  /** The message this answers: threading, and who it went to. The quote is already in the body. */
  replyTo: ComposeReplyTo | null;
  attachments: AttachmentInput[];
}

/** A Drafts list row. */
export interface DraftSummary {
  id: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  snippet: string;
  /** Milliseconds. */
  updatedAt: number;
  attachmentCount: number;
}

/** The storage versions a save was based on (0 = not stored yet), and which attachments are stored. */
export interface DraftBase {
  head: number;
  body: number;
  atts: string[];
}

export const NEW_DRAFT_BASE: DraftBase = { head: 0, body: 0, atts: [] };

export interface LoadedDraft {
  id: string;
  content: DraftContent;
  base: DraftBase;
  updatedAt: number;
}

/** A save found the draft changed (or gone) on another device since it was opened here. */
export class DraftConflictError extends Error {
  constructor() {
    super('this draft was changed on another device');
    this.name = 'DraftConflictError';
  }
}

interface StoredAttachment {
  id: string;
  filename: string;
  contentType: string;
  sizeBytes: number;
  contentHash: string;
  contentId?: string;
  disposition?: string;
}
interface StoredHead {
  v: 1;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  snippet: string;
  updatedAt: number;
  attachments: StoredAttachment[];
}
interface StoredBody {
  v: 1;
  pending: DraftContent['pending'];
  showCcBcc: boolean;
  rich: boolean;
  text: string;
  html: string;
  replyTo: ComposeReplyTo | null;
}
interface StoredBytes { content: string }

/** This device's copy of a draft the relay does not have yet. */
interface LocalDraft {
  id: string;
  content: DraftContent;
  base: DraftBase;
  updatedAt: number;
}

const headKey = (id: string) => 'drafts/' + id;
const bodyKey = (id: string) => 'draft-body/' + id;
const attPrefix = (id: string) => `draft-att/${id}/`;
const attKey = (id: string, attId: string) => attPrefix(id) + attId;
const idFromKey = (key: string) => key.slice(key.indexOf('/') + 1);

/** A fresh draft id: 16 random bytes, hex. */
export function newDraftId(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

const SNIPPET_CHARS = 140;

/** The row's preview line: the start of the text, whitespace folded. */
export function draftSnippet(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length > SNIPPET_CHARS ? flat.slice(0, SNIPPET_CHARS - 1) + '…' : flat;
}

/**
 * Whether a draft holds anything worth keeping. `untouchedText` is what the body starts as before
 * anyone types (the signature, a reply's quote), so a composer opened and closed again leaves
 * nothing behind. A reply's prefilled recipients count only once something else was written.
 */
export function draftHasContent(c: DraftContent, untouchedText: string): boolean {
  const pending = c.pending.to.trim() || c.pending.cc.trim() || c.pending.bcc.trim();
  const typed = c.text.trim() !== untouchedText.trim();
  if (c.replyTo) return !!(typed || c.subject.trim() !== replySubject(c.replyTo.subject).trim() || c.attachments.length || pending || c.bcc.length);
  return !!(typed || c.subject.trim() || c.attachments.length || pending || c.to.length || c.cc.length || c.bcc.length);
}

/** The subject a reply starts with. One rule, shared with the composer. */
export function replySubject(subject: string): string {
  return subject ? `Re: ${subject.replace(/^Re:\s*/i, '')}` : '';
}

/**
 * Put a stored draft's inline images back on screen: the editor shows each one from a data: URI
 * and remembers its Content-ID (RichTextEditor), while the stored HTML carries only the cid:
 * reference. An image whose bytes are missing keeps its reference and shows as broken, rather than
 * being dropped from the message without a word.
 */
export function inlinePreviews(html: string, attachments: AttachmentInput[]): string {
  const byCid = new Map(attachments.filter(a => a.contentId).map(a => [a.contentId!, a]));
  return html.replace(/src="cid:([^"]*)"/g, (whole, cid: string) => {
    const a = byCid.get(cid);
    if (!a) return whole;
    return `src="data:${a.contentType};base64,${toBase64(a.content)}" data-cid="${cid}"`;
  });
}

function storedAttachment(a: AttachmentInput): StoredAttachment {
  return {
    id: toHex(a.attachmentId),
    filename: a.filename,
    contentType: a.contentType,
    sizeBytes: a.sizeBytes,
    contentHash: toBase64(a.contentHash),
    ...(a.contentId ? { contentId: a.contentId } : {}),
    ...(a.disposition ? { disposition: a.disposition } : {}),
  };
}

function summaryOf(id: string, h: Pick<StoredHead, 'from' | 'to' | 'cc' | 'bcc' | 'subject' | 'snippet' | 'updatedAt'>, attachmentCount: number): DraftSummary {
  return { id, from: h.from, to: h.to, cc: h.cc, bcc: h.bcc, subject: h.subject, snippet: h.snippet, updatedAt: h.updatedAt, attachmentCount };
}

/** The personal-store calls a DraftStore makes; PersonalStore in the app, a map in tests. */
export type DraftKv = Pick<PersonalStore, 'get' | 'put' | 'list' | 'listKeys' | 'delete'>;

/** Where this device keeps drafts the relay does not have yet; IndexedDB in the app. */
export interface DraftBackstop {
  get(key: string): Promise<LocalDraft | undefined>;
  put(key: string, value: LocalDraft): Promise<void>;
  delete(key: string): Promise<void>;
  entries(prefix: string): Promise<Array<[string, LocalDraft]>>;
}

const idbBackstop: DraftBackstop = {
  get: key => idbGet<LocalDraft>(PERSONAL_STORE, key),
  put: (key, value) => idbPut(PERSONAL_STORE, key, value),
  delete: key => idbDelete(PERSONAL_STORE, key),
  entries: prefix => idbEntriesWithPrefix<LocalDraft>(PERSONAL_STORE, prefix),
};

const localPrefix = (address: string) => `draft::${address.trim().toLowerCase()}::`;

/** Remove an account's unsaved drafts from this device (the account is being removed from it). */
export function forgetLocalDrafts(address: string): Promise<void> {
  return idbDeletePrefix(PERSONAL_STORE, localPrefix(address));
}

/**
 * How long a device copy must sit untouched before the Drafts list uploads it on its own. Anything
 * younger may belong to a composer that is still open in another tab, which will save it itself.
 */
export const LOCAL_SETTLE_MS = 60_000;

export class DraftStore {
  private kv: DraftKv;
  private local: DraftBackstop | null;
  private prefix: string;

  /** `keepLocal` false: keep nothing on this device (a temporary session). */
  constructor(keys: WorkingKeys, opts: { keepLocal: boolean; kv?: DraftKv; backstop?: DraftBackstop }) {
    this.kv = opts.kv ?? new PersonalStore(keys);
    this.local = opts.keepLocal ? (opts.backstop ?? idbBackstop) : null;
    this.prefix = localPrefix(keys.address);
  }

  /** Whether this device keeps a copy of what it is writing until the relay has it. */
  get keepsLocal(): boolean {
    return this.local !== null;
  }

  /** The Drafts list: the relay's rows, with this device's newer copies in their place. */
  async list(): Promise<DraftSummary[]> {
    const rows = new Map<string, DraftSummary>();
    for (const e of await this.kv.list<StoredHead>('drafts/')) {
      const id = idFromKey(e.key);
      rows.set(id, summaryOf(id, e.value, e.value.attachments.length));
    }
    for (const d of await this.localDrafts()) {
      const had = rows.get(d.id);
      // A copy based on a stored row that has since gone was sent or discarded on another device;
      // that decision stands, and the copy is dropped (settleLocal) rather than resurrected here.
      if (!had && d.base.head > 0) continue;
      if (had && had.updatedAt > d.updatedAt) continue;
      rows.set(d.id, summaryOf(d.id, { ...d.content, snippet: draftSnippet(d.content.text), updatedAt: d.updatedAt }, d.content.attachments.length));
    }
    return [...rows.values()].sort((a, b) => b.updatedAt - a.updatedAt);
  }

  /** Open a draft: this device's copy when it has one, else the relay's. Null when it is gone. */
  async load(id: string): Promise<LoadedDraft | null> {
    const mine = await this.local?.get(this.prefix + id);
    if (mine) return { id, content: mine.content, base: mine.base, updatedAt: mine.updatedAt };
    return this.loadStored(id);
  }

  private async loadStored(id: string): Promise<LoadedDraft | null> {
    const head = await this.kv.get<StoredHead>(headKey(id));
    if (!head) return null;
    const body = await this.kv.get<StoredBody>(bodyKey(id));
    if (!body) return null;
    const attachments: AttachmentInput[] = [];
    const atts: string[] = [];
    for (const a of head.value.attachments) {
      const bytes = await this.kv.get<StoredBytes>(attKey(id, a.id));
      // A part that never made it up is left out rather than failing the draft; the rest is the
      // message, and the composer shows what is attached.
      if (!bytes) continue;
      const content = fromBase64(bytes.value.content);
      atts.push(a.id);
      attachments.push({
        attachmentId: fromHex(a.id),
        filename: a.filename,
        contentType: a.contentType,
        sizeBytes: a.sizeBytes,
        contentHash: fromBase64(a.contentHash),
        content,
        ...(a.contentId ? { contentId: a.contentId } : {}),
        ...(a.disposition ? { disposition: a.disposition } : {}),
      });
    }
    const h = head.value;
    const b = body.value;
    return {
      id,
      updatedAt: h.updatedAt,
      base: { head: head.version, body: body.version, atts },
      content: {
        from: h.from, to: h.to, cc: h.cc, bcc: h.bcc, subject: h.subject,
        pending: b.pending, showCcBcc: b.showCcBcc, rich: b.rich, text: b.text, html: b.html,
        replyTo: b.replyTo, attachments,
      },
    };
  }

  /** Whether the relay still holds the draft (a conflict: changed elsewhere, or sent/discarded there). */
  async isStored(id: string): Promise<boolean> {
    return (await this.kv.get(headKey(id))) !== null;
  }

  /** Keep the latest state on this device until the relay has it. A no-op in a temporary session. */
  async saveLocal(id: string, content: DraftContent, base: DraftBase, updatedAt: number): Promise<void> {
    await this.local?.put(this.prefix + id, { id, content, base, updatedAt });
  }

  /** Drop this device's copy, unless a newer state has been written there since `updatedAt`. */
  async clearLocal(id: string, updatedAt?: number): Promise<void> {
    if (!this.local) return;
    const key = this.prefix + id;
    if (updatedAt !== undefined) {
      const cur = await this.local.get(key);
      if (cur && cur.updatedAt > updatedAt) return;
    }
    await this.local.delete(key);
  }

  /**
   * Store a draft on the relay and return the versions it is now at.
   *
   * Attachments first, then the body, then the row: the row is what makes a draft appear in the
   * list, so it is written last and never points at a body that is not there. The body and row are
   * compare-and-swap against `base`, so a save that would overwrite another device's newer copy
   * throws DraftConflictError instead; `force` overwrites, for "keep this copy".
   */
  async save(id: string, content: DraftContent, base: DraftBase, updatedAt: number, force = false): Promise<DraftBase> {
    const want = new Map(content.attachments.map(a => [toHex(a.attachmentId), a]));
    const stored = new Set(base.atts);
    for (const [attId, a] of want) {
      if (stored.has(attId)) continue;
      await this.kv.put(attKey(id, attId), { content: toBase64(a.content) } satisfies StoredBytes);
      stored.add(attId);
    }

    const body: StoredBody = {
      v: 1, pending: content.pending, showCcBcc: content.showCcBcc, rich: content.rich,
      text: content.text, html: content.html, replyTo: content.replyTo,
    };
    const head: StoredHead = {
      v: 1, from: content.from, to: content.to, cc: content.cc, bcc: content.bcc, subject: content.subject,
      snippet: draftSnippet(content.text), updatedAt, attachments: content.attachments.map(storedAttachment),
    };
    let bodyVersion: number;
    let headVersion: number;
    try {
      bodyVersion = await this.kv.put(bodyKey(id), body, force ? 0 : base.body);
      headVersion = await this.kv.put(headKey(id), head, force ? 0 : base.head);
    } catch (err) {
      if (err instanceof StorageConflictError) throw new DraftConflictError();
      throw err;
    }

    // Parts taken out of the message since the last save. After the row, so a row never names a
    // part that was already deleted; a failure here only leaves an orphan the next save retries.
    for (const attId of [...stored]) {
      if (want.has(attId)) continue;
      try {
        await this.kv.delete(attKey(id, attId));
        stored.delete(attId);
      } catch { /* retried on the next save */ }
    }
    return { head: headVersion, body: bodyVersion, atts: [...stored] };
  }

  /** Remove a draft everywhere: sent, or discarded. The row goes first, so it leaves the list at once. */
  async delete(id: string): Promise<void> {
    await this.clearLocal(id);
    await this.kv.delete(headKey(id));
    await this.kv.delete(bodyKey(id));
    for (const { key } of await this.kv.listKeys(attPrefix(id))) await this.kv.delete(key);
  }

  /**
   * Upload what this device kept and no composer is going to save: copies left by a tab that
   * closed, or written while the relay could not be reached. Copies younger than LOCAL_SETTLE_MS
   * are left to the composer that may still own them, and a copy whose draft was removed on
   * another device meanwhile is dropped. Returns whether anything changed.
   */
  async settleLocal(skip: ReadonlySet<string>, now = Date.now()): Promise<boolean> {
    let changed = false;
    for (const d of await this.localDrafts()) {
      if (skip.has(d.id) || now - d.updatedAt < LOCAL_SETTLE_MS) continue;
      try {
        await this.save(d.id, d.content, d.base, d.updatedAt);
        await this.clearLocal(d.id, d.updatedAt);
        changed = true;
      } catch (err) {
        if (!(err instanceof DraftConflictError)) continue; // offline, still: try again next time
        if (d.base.head > 0 && !(await this.isStored(d.id))) {
          await this.clearLocal(d.id, d.updatedAt);
          changed = true;
        }
        // Otherwise both copies changed. Kept, and listed; opening it shows this device's copy and
        // its next save asks which one to keep.
      }
    }
    return changed;
  }

  private async localDrafts(): Promise<LocalDraft[]> {
    if (!this.local) return [];
    try {
      return (await this.local.entries(this.prefix)).map(([, v]) => v);
    } catch {
      return [];
    }
  }
}
