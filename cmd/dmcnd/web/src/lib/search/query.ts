// The mail search box: what a query means, and whether one message matches it. Pure.
//
// Structured operators read the decrypted header every row already holds (sender, recipients,
// subject, date, attachment count) plus the owner's own flags and labels, so they need nothing
// from the index and apply the moment they are typed. Only two things need the on-device index:
// bare words, which are also looked for in message text, and filename:, which reads attachment
// names. Those arrive as `hits`, a little later; until they do, a row matches on its header alone.
//
//   from:x  to:x  subject:x  has:attachment  filename:x  is:unread|read|starred  label:x
//   before:YYYY-MM-DD  after:YYYY-MM-DD  word  "quoted words"  -anything (negates it)
//
// Clauses all have to hold. A value can be quoted (from:"Alice Smith"). Anything that is not a
// known operator with a usable value is an ordinary word, so a colon in a search ("re:", a time,
// a URL) never turns it into an error or silently into nothing.

import { fold } from './tokenize';

export type Clause =
  | { neg: boolean; kind: 'from' | 'to' | 'subject' | 'label' | 'word'; value: string }
  | { neg: boolean; kind: 'filename'; value: string; glob: RegExp | null }
  | { neg: boolean; kind: 'has'; value: 'attachment' }
  | { neg: boolean; kind: 'is'; value: 'unread' | 'read' | 'starred' }
  | { neg: boolean; kind: 'before' | 'after'; at: number };

export interface ParsedQuery {
  clauses: Clause[];
  /** Word values to look up in message text (and attachment names). */
  words: string[];
  /** filename: values to look up in attachment names. */
  filenames: string[];
}

/** Which messages the index found for each word and each filename: value, by message hash. */
export interface Hits {
  words: Map<string, Set<string>>;
  files: Map<string, Set<string>>;
}

export interface MatchContext {
  /** The owner's name for an address (a contact's name), or the address itself. */
  nameFor: (address: string) => string;
  isRead: (hash: string) => boolean;
  isStarred: (hash: string) => boolean;
  /** Names of the labels on a message. */
  labelNames: (hash: string) => string[];
}

/** The header fields a match reads — a subset of Preview, so tests need not build a whole one. */
export interface Matchable {
  hash: string;
  senderAddress: string;
  senderDisplay: string;
  recipientAddress: string;
  deliveredTo?: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  snippet: string;
  sentAt: number;
  attachmentCount: number;
}

const FIELD_OPS = new Set(['from', 'to', 'subject', 'label', 'filename', 'has', 'is', 'before', 'after']);

/**
 * A filename pattern as a whole-name match, when it has a wildcard: `*` is any run of characters
 * and `?` exactly one. Without one it is null, and the value matches anywhere in a name.
 */
export function globToRegExp(pattern: string): RegExp | null {
  if (!/[*?]/.test(pattern)) return null;
  const body = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${body}$`, 's');
}

/** Midnight at the start of a YYYY-MM-DD day, local time, in Unix seconds; null if not a date. */
function dayStart(v: string): number | null {
  const m = /^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/.exec(v);
  if (!m) return null;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const date = new Date(y, mo - 1, d);
  if (date.getFullYear() !== y || date.getMonth() !== mo - 1 || date.getDate() !== d) return null;
  return Math.floor(date.getTime() / 1000);
}

// One clause from an operator and its (already unquoted) value, or null when the pair is not a
// usable operator — the caller then keeps the raw text as a word.
function operator(op: string, raw: string, neg: boolean): Clause | null {
  const value = fold(raw.trim());
  if (!value) return null;
  switch (op) {
    case 'from': case 'to': case 'subject': case 'label':
      return { neg, kind: op, value };
    case 'filename':
      return { neg, kind: 'filename', value, glob: globToRegExp(value) };
    case 'has':
      return value === 'attachment' || value === 'attachments' ? { neg, kind: 'has', value: 'attachment' } : null;
    case 'is':
      return value === 'unread' || value === 'read' || value === 'starred' ? { neg, kind: 'is', value } : null;
    case 'before': case 'after': {
      const at = dayStart(value);
      return at === null ? null : { neg, kind: op, at };
    }
  }
  return null;
}

export function parseQuery(input: string): ParsedQuery {
  const clauses: Clause[] = [];
  const s = input.trim();
  let i = 0;
  const ws = (c: string | undefined) => c === undefined || /\s/.test(c);

  // A value runs to the next space, or, opened with a quote, to the closing quote (or the end,
  // while it is still being typed).
  const readValue = (): string => {
    if (s[i] === '"') {
      const end = s.indexOf('"', i + 1);
      const v = s.slice(i + 1, end < 0 ? s.length : end);
      i = end < 0 ? s.length : end + 1;
      return v;
    }
    const start = i;
    while (!ws(s[i])) i++;
    return s.slice(start, i);
  };

  while (i < s.length) {
    while (i < s.length && ws(s[i])) i++;
    if (i >= s.length) break;
    const start = i;
    const neg = s[i] === '-' && !ws(s[i + 1]);
    if (neg) i++;
    const op = /^([a-zA-Z]+):/.exec(s.slice(i));
    let clause: Clause | null = null;
    if (op && FIELD_OPS.has(op[1].toLowerCase()) && !ws(s[i + op[0].length])) {
      i += op[0].length;
      clause = operator(op[1].toLowerCase(), readValue(), neg);
      if (!clause) {
        // Not a usable operator after all: the whole thing, as typed, is a word.
        const raw = s.slice(neg ? start + 1 : start, i);
        const value = fold(raw.replace(/"/g, ''));
        if (value) clause = { neg, kind: 'word', value };
      }
    } else {
      const value = fold(readValue());
      if (value) clause = { neg, kind: 'word', value };
    }
    if (clause) clauses.push(clause);
  }

  const words: string[] = [];
  const filenames: string[] = [];
  for (const c of clauses) {
    if (c.kind === 'word' && !words.includes(c.value)) words.push(c.value);
    if (c.kind === 'filename' && !filenames.includes(c.value)) filenames.push(c.value);
  }
  return { clauses, words, filenames };
}

/** Whether a filename matches a filename: value (folded on both sides). */
export function filenameMatches(name: string, value: string, glob: RegExp | null): boolean {
  const n = fold(name);
  return glob ? glob.test(n) : n.includes(value);
}

const anyIncludes = (fields: string[], v: string) => fields.some(f => fold(f).includes(v));

function senderFields(m: Matchable, ctx: MatchContext): string[] {
  return [m.senderAddress, m.senderDisplay, ctx.nameFor(m.senderAddress)];
}

function recipientFields(m: Matchable, ctx: MatchContext): string[] {
  const addrs = [m.recipientAddress, m.deliveredTo ?? '', ...m.to, ...m.cc, ...m.bcc].filter(Boolean);
  return [...addrs, ...addrs.map(a => ctx.nameFor(a))];
}

function holds(m: Matchable, c: Clause, ctx: MatchContext, hits: Hits | null): boolean {
  switch (c.kind) {
    case 'from': return anyIncludes(senderFields(m, ctx), c.value);
    case 'to': return anyIncludes(recipientFields(m, ctx), c.value);
    case 'subject': return fold(m.subject).includes(c.value);
    case 'label': return ctx.labelNames(m.hash).some(n => fold(n) === c.value);
    case 'has': return m.attachmentCount > 0;
    case 'is': return c.value === 'starred' ? ctx.isStarred(m.hash) : (c.value === 'read') === ctx.isRead(m.hash);
    case 'before': return m.sentAt < c.at;
    case 'after': return m.sentAt >= c.at;
    case 'filename': return hits?.files.get(c.value)?.has(m.hash) ?? false;
    case 'word':
      return anyIncludes([...senderFields(m, ctx), ...recipientFields(m, ctx), m.subject, m.snippet], c.value)
        || (hits?.words.get(c.value)?.has(m.hash) ?? false);
  }
}

/** Whether a message matches every clause of a query. An empty query matches everything. */
export function matches(m: Matchable, q: ParsedQuery, ctx: MatchContext, hits: Hits | null): boolean {
  for (const c of q.clauses) if (holds(m, c, ctx, hits) === c.neg) return false;
  return true;
}
