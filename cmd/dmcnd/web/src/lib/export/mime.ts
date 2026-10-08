// One message, as the RFC 5322 file a mail program can import.
//
// Native DMCN mail is rebuilt from what the reader decrypted, in the same shape the bridge gives
// it on its way out to ordinary email (internal/bridge/mime.go, buildMIME): the same Message-ID
// form and threading headers, so a conversation exported here lines up with the copies its legacy
// participants hold, and the same part layout. Mail that came IN through the bridge is not rebuilt
// at all: the bridge kept the email it received, and that original, byte for byte, is the better
// record. It still carries the sender's own headers and DKIM signature, so it can be checked again
// somewhere else. Either way a few X-DMCN- lines on top say what this client checked.
//
// Lines end in CRLF here, as RFC 5322 has them; the mbox writer (mbox.ts) turns them into the
// file's own line ends.

import type { Preview } from '../api/mailboxRest';
import type { DecryptedAttachment } from '../crypto/split';
import { toBase64 } from '../crypto/keys';

const CRLF = '\r\n';
const enc = new TextEncoder();

/** The bridge's verdict on a bridged message, as verifyBridgeAttestation gave it. */
export interface BridgeVerdict {
  verified: boolean;
  spf?: string;
  dkim?: string;
  dmarc?: string;
  reason?: string;
}

/** Everything one exported message is written from. */
export interface ExportItem {
  /** The row, from the header the open verified (FullBody.row). */
  row: Preview;
  /** Hex of reply_to_id, '' when it is not a reply. */
  replyToId: string;
  text: string;
  html?: string;
  /** The attachments the sender attached: protocol records and control payloads already removed. */
  attachments: DecryptedAttachment[];
  /** For bridged mail, the email the bridge received, written instead of a rebuilt message. */
  original?: Uint8Array;
  /** For bridged mail, the checks the bridge ran, and whether its account of them verified. */
  bridge?: BridgeVerdict | null;
  /** A Sent copy: the owner's own record, so it keeps the Bcc line a recipient never sees. */
  sent: boolean;
  /** The owner's state for this message, written as the headers mail programs read it from. */
  read?: boolean;
  starred?: boolean;
  labels?: string[];
  /** Where it is filed besides the folder being exported: 'Archive', or a folder's name. */
  place?: string;
  /**
   * The Message-ID each message is exported under, by the hex of its DMCN message id, so a reply's
   * In-Reply-To and References name the parent as the export wrote it: under the parent sender's
   * domain, or the original's own Message-ID for bridged mail. An id not in it falls back to the
   * replier's domain, as the bridge's outbound copy names it.
   */
  ids?: ReadonlyMap<string, string>;
}

/**
 * renderMessage writes one message as RFC 5322 bytes with CRLF line ends, in chunks: an
 * attachment's encoding is its own chunk rather than part of one big copy of the message, and the
 * caller writes them out one by one. Every chunk but the last ends at the end of a line.
 */
export function renderMessage(item: ExportItem, boundary: () => string = randomBoundary): Uint8Array[] {
  const state = stateHeaders(item);
  if (item.original) {
    const top = [...bridgeHeaders(item.bridge), ...dmcnHeaders(item), ...state].join(CRLF) + CRLF;
    return [enc.encode(top), ...withoutOwnHeaders(item.original)];
  }
  const out = new Chunks();
  out.text([...envelopeHeaders(item), ...dmcnHeaders(item), ...state, 'MIME-Version: 1.0'].join(CRLF) + CRLF);
  body(item, boundary, out);
  return out.done();
}

// Chunks gathers a message as text runs and byte runs, encoding each text run once.
class Chunks {
  private parts: Uint8Array[] = [];
  private pending = '';
  text(s: string) { this.pending += s; }
  bytes(b: Uint8Array) { this.flush(); this.parts.push(b); }
  done(): Uint8Array[] { this.flush(); return this.parts; }
  private flush() { if (this.pending) { this.parts.push(enc.encode(this.pending)); this.pending = ''; } }
}

// --- a bridged original ----------------------------------------------------------------------

// The header fields this export writes itself. A sender can put any of them into the email the
// bridge received, so they are taken out of the original before it is written under ours:
// otherwise a forged "X-DMCN-Bridge-Verified: yes" would sit in the same block as the real
// verdict, and a program that reads the last one, or any, would believe it.
const OWN_FIELDS = /^(x-dmcn-[!-9;-~]*|status|x-status|x-keywords)$/i;

interface HeaderBlock {
  /** Each field: its name, and the bytes [start, end) it spans, continuation lines included. */
  fields: Array<{ name: string; start: number; end: number }>;
  /** Where the header block ends: the start of the blank line, or the end of the message. */
  end: number;
}

// headerBlock finds the fields of a message's header, working on bytes (the original is written
// back byte for byte, so nothing is decoded but the header names).
function headerBlock(msg: Uint8Array): HeaderBlock {
  const fields: HeaderBlock['fields'] = [];
  let at = 0;
  while (at < msg.length) {
    let eol = msg.indexOf(0x0a, at);
    const next = eol < 0 ? msg.length : eol + 1;
    if (eol < 0) eol = msg.length;
    const lineEnd = eol > at && msg[eol - 1] === 0x0d ? eol - 1 : eol;
    if (lineEnd === at) return { fields, end: at }; // the blank line
    const first = msg[at];
    if ((first === 0x20 || first === 0x09) && fields.length) {
      fields[fields.length - 1].end = next; // a continuation of the field above
    } else {
      const colon = msg.indexOf(0x3a, at);
      const name = colon > at && colon < lineEnd ? latin1(msg.subarray(at, colon)).trim() : '';
      fields.push({ name, start: at, end: next });
    }
    at = next;
  }
  return { fields, end: msg.length };
}

const latin1 = (b: Uint8Array) => String.fromCharCode(...b.subarray(0, 4096));

/** withoutOwnHeaders returns the original without OWN_FIELDS, as views into it where it can. */
export function withoutOwnHeaders(original: Uint8Array): Uint8Array[] {
  const { fields } = headerBlock(original);
  if (!fields.some(f => OWN_FIELDS.test(f.name))) return [original];
  const out: Uint8Array[] = [];
  let from = 0;
  for (const f of fields) {
    if (!OWN_FIELDS.test(f.name)) continue;
    if (f.start > from) out.push(original.subarray(from, f.start));
    from = f.end;
  }
  if (original.length > from) out.push(original.subarray(from));
  return out;
}

/** originalMessageId is the original's own Message-ID, angle brackets included, if it has one. */
export function originalMessageId(original: Uint8Array): string | undefined {
  const f = headerBlock(original).fields.find(x => x.name.toLowerCase() === 'message-id');
  if (!f) return undefined;
  const value = latin1(original.subarray(f.start, f.end)).replace(/^[^:]*:/, '').replace(/\r?\n[ \t]+/g, ' ');
  return value.match(/<[^<>\s]+>/)?.[0];
}

/**
 * exportMessageId is the Message-ID a native message is exported under: its id at its sender's
 * domain, the form the bridge gives it on the way out to ordinary email.
 */
export function exportMessageId(hex: string, senderAddress: string): string {
  return msgId(hex, domainOf(senderAddress));
}

// --- headers ---------------------------------------------------------------------------------

function envelopeHeaders(item: ExportItem): string[] {
  const r = item.row;
  const domain = domainOf(r.senderAddress);
  const out = [
    header('From', mailbox(r.senderAddress, r.senderDisplay)),
  ];
  // The full audience, as the bridge writes it; the one copy's recipient when there is none.
  const to = r.to.length ? r.to : [r.recipientAddress];
  out.push(addressHeader('To', to));
  if (r.cc.length) out.push(addressHeader('Cc', r.cc));
  if (item.sent && r.bcc.length) out.push(addressHeader('Bcc', r.bcc));
  out.push(header('Subject', encodeWords(clean(r.subject))));
  out.push(header('Date', rfc5322Date(r.sentAt)));
  if (isId(r.messageId)) out.push(header('Message-ID', msgId(r.messageId, domain)));
  if (isId(item.replyToId)) {
    // As buildMIME lays them out: In-Reply-To is the parent; References leads with the thread root
    // as a stable anchor, dropped when there is none or it is the parent itself. Each is named as
    // this export named it (item.ids), so the reply sits under its parent in a mail program.
    const idOf = (hex: string) => item.ids?.get(hex.toLowerCase()) ?? msgId(hex, domain);
    const parent = idOf(item.replyToId);
    out.push(header('In-Reply-To', parent));
    const refs = isId(r.threadId) && r.threadId !== item.replyToId ? `${idOf(r.threadId)} ${parent}` : parent;
    out.push(header('References', clean(refs)));
  }
  return out;
}

function dmcnHeaders(item: ExportItem): string[] {
  const out: string[] = [];
  // The key the header's signature verified under, which is what the address was proven against.
  // Not for bridged mail: that header was signed by the bridge, and the original's own From and
  // DKIM signature are the sender's account of themselves.
  if (item.row.senderPublicKey && !item.original) out.push(header('X-DMCN-Sender-Key', item.row.senderPublicKey));
  // An isolated alias's copy is sealed to the alias, and this says which address it came to.
  if (item.row.deliveredTo) out.push(header('X-DMCN-Delivered-To', clean(item.row.deliveredTo)));
  return out;
}

function bridgeHeaders(v: BridgeVerdict | null | undefined): string[] {
  if (!v) return [header('X-DMCN-Bridge-Verified', 'no (no record of the checks)')];
  const checks = (['spf', 'dkim', 'dmarc'] as const).map(k => `${k}=${token(v[k]) || 'none'}`).join('; ');
  return [
    header('X-DMCN-Bridge-Checks', checks),
    header('X-DMCN-Bridge-Verified', v.verified ? 'yes' : `no (${clean(v.reason || 'not verified')})`),
  ];
}

// Status / X-Status are the mbox convention for read and flagged (mutt, Dovecot, Thunderbird's
// import); X-Keywords carries labels the way Dovecot and Thunderbird keep keywords.
function stateHeaders(item: ExportItem): string[] {
  const out = [header('Status', item.read || item.sent ? 'RO' : 'O')];
  if (item.starred) out.push(header('X-Status', 'F'));
  const labels = (item.labels ?? []).map(l => clean(l).replace(/,/g, ' ').trim()).filter(Boolean);
  if (labels.length) out.push(header('X-Keywords', encodeWords(labels.join(', '))));
  if (item.place) out.push(header('X-DMCN-Folder', encodeWords(clean(item.place))));
  return out;
}

function header(name: string, value: string): string {
  return `${name}: ${value}`;
}

function addressHeader(name: string, addrs: string[]): string {
  // One address per folded line once the list grows: no line runs long, and nothing is split
  // inside an address.
  const list = addrs.map(a => clean(a)).filter(Boolean);
  return header(name, list.length > 2 ? list.join(',' + CRLF + ' ') : list.join(', '));
}

function mailbox(address: string, display: string): string {
  const addr = clean(address);
  const name = clean(display);
  if (!name) return addr;
  if (/[^\x20-\x7e]/.test(name)) return `${encodeWords(name)} <${addr}>`;
  return `"${name.replace(/[\\"]/g, c => '\\' + c)}" <${addr}>`;
}

/** clean makes a signed header string safe to write as one header line. A native sender signs any
 *  subject they like, CR and LF included, and a line break there would start a header of theirs. */
export function clean(s: string): string {
  // eslint-disable-next-line no-control-regex
  return (s ?? '').replace(/[\r\n\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+/g, ' ').trim();
}

const token = (s: string | undefined) => (s ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '');

const isId = (hex: string | undefined) => !!hex && /^[0-9a-f]+$/i.test(hex) && /[^0]/.test(hex);

const msgId = (hex: string, domain: string) => `<${hex.toLowerCase()}@${domain}>`;

function domainOf(address: string): string {
  const at = address.lastIndexOf('@');
  const d = at >= 0 ? clean(address.slice(at + 1)).toLowerCase().replace(/[^a-z0-9.-]/g, '') : '';
  return d || 'dmcn.invalid';
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n: number) => String(n).padStart(2, '0');

/** rfc5322Date renders Unix seconds as an RFC 5322 date, in UTC. */
export function rfc5322Date(sec: number): string {
  const d = new Date(sec * 1000);
  return `${DAYS[d.getUTCDay()]}, ${two(d.getUTCDate())} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} `
    + `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} +0000`;
}

/**
 * encodeWords returns s unchanged when it is printable ASCII, else as RFC 2047 encoded words.
 * Each word holds at most 45 bytes of UTF-8 (60 base64 characters, 72 with its wrapping, inside
 * the 75 RFC 2047 allows), split only between characters, and the words are folded one per line.
 */
export function encodeWords(s: string): string {
  if (!/[^\x20-\x7e]/.test(s)) return s;
  const words: number[][] = [];
  const chunk: number[] = [];
  for (const ch of s) {
    const b = enc.encode(ch);
    if (chunk.length + b.length > 45) { words.push(chunk.splice(0)); }
    chunk.push(...b);
  }
  if (chunk.length) words.push(chunk);
  return words.map(w => `=?UTF-8?B?${toBase64(new Uint8Array(w))}?=`).join(CRLF + ' ');
}

// --- body ------------------------------------------------------------------------------------

function body(item: ExportItem, boundary: () => string, out: Chunks): void {
  const atts = item.attachments;
  const hasHtml = item.html !== undefined;
  if (!atts.length && !hasHtml) { out.text(textPartHeaders('text/plain') + CRLF + quotedPrintable(item.text)); return; }
  if (!atts.length) { out.text(alternative(item, boundary)); return; }

  const b = boundary();
  out.text(`Content-Type: multipart/mixed; boundary="${b}"` + CRLF + CRLF + `--${b}` + CRLF);
  out.text(hasHtml ? alternative(item, boundary) : textPartHeaders('text/plain') + CRLF + quotedPrintable(item.text));
  for (const a of atts) {
    out.text(CRLF + `--${b}` + CRLF + attachmentHeaders(a) + CRLF);
    out.bytes(base64Lines(a.content));
  }
  out.text(CRLF + `--${b}--` + CRLF);
}

// The least rich part first (RFC 2046 §5.1.4), as buildMIME writes it.
function alternative(item: ExportItem, boundary: () => string): string {
  const b = boundary();
  return `Content-Type: multipart/alternative; boundary="${b}"` + CRLF + CRLF
    + `--${b}` + CRLF + textPartHeaders('text/plain') + CRLF + quotedPrintable(item.text) + CRLF
    + `--${b}` + CRLF + textPartHeaders('text/html') + CRLF + quotedPrintable(item.html ?? '') + CRLF
    + `--${b}--` + CRLF;
}

function textPartHeaders(type: string): string {
  return `Content-Type: ${type}; charset=utf-8` + CRLF + 'Content-Transfer-Encoding: quoted-printable' + CRLF;
}

function attachmentHeaders(a: DecryptedAttachment): string {
  const type = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(a.contentType) ? a.contentType.toLowerCase() : 'application/octet-stream';
  const name = clean(a.filename) || 'attachment';
  const inline = a.disposition === 'inline' && !!a.contentId;
  let h = `Content-Type: ${type}; ${filenameParam('name', name)}` + CRLF;
  h += `Content-Disposition: ${inline ? 'inline' : 'attachment'}; ${filenameParam('filename', name)}` + CRLF;
  if (a.contentId) h += `Content-ID: <${clean(a.contentId).replace(/[<>]/g, '')}>` + CRLF;
  return h + 'Content-Transfer-Encoding: base64' + CRLF;
}

/**
 * filenameParam writes a MIME parameter: quoted when it is printable ASCII, RFC 2231
 * (`name*=UTF-8''…`) otherwise, which is what current mail programs read for a non-ASCII name.
 */
export function filenameParam(param: string, value: string): string {
  if (!/[^\x20-\x7e]/.test(value)) return `${param}="${value.replace(/[\\"]/g, c => '\\' + c)}"`;
  const pct = Array.from(enc.encode(value), b =>
    /[A-Za-z0-9!#$&+.^_`|~-]/.test(String.fromCharCode(b)) ? String.fromCharCode(b) : '%' + b.toString(16).toUpperCase().padStart(2, '0'),
  ).join('');
  return `${param}*=UTF-8''${pct}`;
}

const B64 = enc.encode('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');

/**
 * base64Lines encodes bytes as base64 in lines of 76 characters, each ended by CRLF, straight into
 * bytes. An attachment can be tens of megabytes, and going through a JS string first would hold
 * it twice more (a string is two bytes a character) on its way to the file.
 */
export function base64Lines(bytes: Uint8Array): Uint8Array {
  const chars = Math.ceil(bytes.length / 3) * 4;
  const out = new Uint8Array(chars + Math.ceil(chars / 76) * 2);
  let at = 0;
  let col = 0;
  for (let i = 0; i < bytes.length; i += 3) {
    const n = bytes.length - i;
    const v = (bytes[i] << 16) | ((n > 1 ? bytes[i + 1] : 0) << 8) | (n > 2 ? bytes[i + 2] : 0);
    out[at++] = B64[(v >> 18) & 63];
    out[at++] = B64[(v >> 12) & 63];
    out[at++] = n > 1 ? B64[(v >> 6) & 63] : 0x3d;
    out[at++] = n > 2 ? B64[v & 63] : 0x3d;
    col += 4;
    if (col === 76 || i + 3 >= bytes.length) { out[at++] = 0x0d; out[at++] = 0x0a; col = 0; }
  }
  return out;
}

/**
 * quotedPrintable encodes text as RFC 2045 quoted-printable over its UTF-8 bytes. Line breaks in
 * the text become CRLF; no encoded line runs past 76 characters (a soft break, `=`, is inserted
 * first); trailing whitespace is encoded so nothing in transit can strip it; and an encoded line
 * that would start with "From " or "." (a soft break's continuation included) has that first
 * character encoded, so neither an mbox reader nor an SMTP hop can mistake or alter it.
 */
export function quotedPrintable(text: string): string {
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  return lines.map(qpLine).join(CRLF) + CRLF;
}

function qpLine(line: string): string {
  const bytes = enc.encode(line);
  const tokens: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    const last = i === bytes.length - 1;
    const literal = (b >= 33 && b <= 126 && b !== 61) || ((b === 32 || b === 9) && !last);
    tokens.push(literal ? String.fromCharCode(b) : '=' + b.toString(16).toUpperCase().padStart(2, '0'));
  }
  let out = '';
  let len = 0;
  for (let i = 0; i < tokens.length; i++) {
    let t = tokens[i];
    if (len + t.length > 75) { out += '=' + CRLF; len = 0; }
    // Every encoded line's start, a soft break's continuation included: a "From " or "." landing
    // there would be read as an mbox separator or altered by an SMTP hop just the same.
    if (len === 0) t = lineStart(tokens, i);
    out += t;
    len += t.length;
  }
  return out;
}

function lineStart(tokens: string[], i: number): string {
  if (tokens[i] === '.') return '=2E';
  if (tokens[i] === 'F' && tokens.slice(i, i + 5).join('') === 'From ') return '=46';
  return tokens[i];
}

function randomBoundary(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return 'dmcn-' + Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}
