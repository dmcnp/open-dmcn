import { describe, expect, it } from 'vitest';
import { filenameMatches, globToRegExp, matches, parseQuery, type Hits, type Matchable, type MatchContext } from './query';

const msg = (over: Partial<Matchable> = {}): Matchable => ({
  hash: 'h1',
  senderAddress: 'alice@example.com',
  senderDisplay: '',
  recipientAddress: 'bob@example.com',
  to: ['bob@example.com'],
  cc: [],
  bcc: [],
  subject: 'Quarterly report',
  snippet: 'Here are the numbers',
  sentAt: Math.floor(new Date(2026, 5, 15, 12).getTime() / 1000),
  attachmentCount: 0,
  ...over,
});

const ctx = (over: Partial<MatchContext> = {}): MatchContext => ({
  nameFor: a => (a === 'alice@example.com' ? 'Alice Smith' : a),
  isRead: () => false,
  isStarred: () => false,
  labelNames: () => [],
  ...over,
});

const hits = (words: Record<string, string[]> = {}, files: Record<string, string[]> = {}): Hits => ({
  words: new Map(Object.entries(words).map(([k, v]) => [k, new Set(v)])),
  files: new Map(Object.entries(files).map(([k, v]) => [k, new Set(v)])),
});

const q = (s: string, m = msg(), c = ctx(), h: Hits | null = null) => matches(m, parseQuery(s), c, h);

describe('parseQuery', () => {
  it('reads operators, quoted values and negation', () => {
    const p = parseQuery('from:"Alice Smith" -has:attachment report');
    expect(p.clauses).toEqual([
      { neg: false, kind: 'from', value: 'alice smith' },
      { neg: true, kind: 'has', value: 'attachment' },
      { neg: false, kind: 'word', value: 'report' },
    ]);
    expect(p.words).toEqual(['report']);
  });

  it('keeps unknown or unusable operators as ordinary words', () => {
    expect(parseQuery('re:meeting').clauses).toEqual([{ neg: false, kind: 'word', value: 're:meeting' }]);
    expect(parseQuery('has:cats').clauses).toEqual([{ neg: false, kind: 'word', value: 'has:cats' }]);
    expect(parseQuery('before:someday').clauses).toEqual([{ neg: false, kind: 'word', value: 'before:someday' }]);
    expect(parseQuery('from: alice').clauses.map(c => c.kind)).toEqual(['word', 'word']);
  });

  it('tolerates a quote still being typed', () => {
    expect(parseQuery('subject:"quarterly rep').clauses).toEqual([{ neg: false, kind: 'subject', value: 'quarterly rep' }]);
  });

  it('collects filename values separately from words', () => {
    const p = parseQuery('filename:*.PDF invoice');
    expect(p.filenames).toEqual(['*.pdf']);
    expect(p.words).toEqual(['invoice']);
  });

  it('is empty for blank input', () => {
    expect(parseQuery('   ').clauses).toEqual([]);
  });
});

describe('globToRegExp', () => {
  it('is null without a wildcard', () => {
    expect(globToRegExp('report.pdf')).toBeNull();
  });

  it('anchors the pattern and escapes everything but * and ?', () => {
    const re = globToRegExp('*.pdf')!;
    expect(re.test('scan.pdf')).toBe(true);
    expect(re.test('scan.pdf.exe')).toBe(false);
    expect(re.test('scanxpdf')).toBe(false);
    expect(globToRegExp('invoice-202?(1)*')!.test('invoice-2026(1) final.docx')).toBe(true);
    expect(globToRegExp('a+b*')!.test('aab.txt')).toBe(false);
  });
});

describe('filenameMatches', () => {
  it('folds the name and matches substrings without a wildcard', () => {
    expect(filenameMatches('Résumé 2026.PDF', 'resume', null)).toBe(true);
    expect(filenameMatches('Résumé 2026.PDF', '*.pdf', globToRegExp('*.pdf'))).toBe(true);
    expect(filenameMatches('notes.txt', '*.pdf', globToRegExp('*.pdf'))).toBe(false);
  });
});

describe('matches', () => {
  it('matches everything for an empty query', () => {
    expect(q('')).toBe(true);
  });

  it('from: reads the address, the header name and the contact name', () => {
    expect(q('from:alice@')).toBe(true);
    expect(q('from:smith')).toBe(true);
    expect(q('from:bob')).toBe(false);
    expect(q('from:ally', msg({ senderDisplay: 'Ally' }))).toBe(true);
  });

  it('to: reads every recipient field', () => {
    expect(q('to:bob')).toBe(true);
    expect(q('to:carol', msg({ cc: ['carol@example.com'] }))).toBe(true);
    expect(q('to:dave', msg({ bcc: ['dave@example.com'] }))).toBe(true);
    expect(q('to:alias', msg({ deliveredTo: 'alias@example.com' }))).toBe(true);
    expect(q('to:alice')).toBe(false);
  });

  it('has:attachment reads the header count', () => {
    expect(q('has:attachment')).toBe(false);
    expect(q('has:attachment', msg({ attachmentCount: 2 }))).toBe(true);
    expect(q('-has:attachment')).toBe(true);
  });

  it('is: and label: read the owner flags', () => {
    expect(q('is:unread')).toBe(true);
    expect(q('is:read')).toBe(false);
    expect(q('is:starred', msg(), ctx({ isStarred: () => true }))).toBe(true);
    expect(q('label:work', msg(), ctx({ labelNames: () => ['Work'] }))).toBe(true);
    expect(q('label:wor', msg(), ctx({ labelNames: () => ['Work'] }))).toBe(false);
  });

  it('before: is exclusive and after: inclusive of the day named', () => {
    expect(q('after:2026-06-15')).toBe(true);
    expect(q('after:2026-06-16')).toBe(false);
    expect(q('before:2026-06-15')).toBe(false);
    expect(q('before:2026-06-16')).toBe(true);
  });

  it('a word matches the header, or the body once the index answers', () => {
    expect(q('quarterly')).toBe(true);
    expect(q('revenue')).toBe(false);
    expect(q('revenue', msg(), ctx(), hits({ revenue: ['h1'] }))).toBe(true);
    expect(q('revenue', msg(), ctx(), hits({ revenue: ['other'] }))).toBe(false);
  });

  it('every clause has to hold', () => {
    expect(q('from:alice revenue', msg(), ctx(), hits({ revenue: ['h1'] }))).toBe(true);
    expect(q('from:bob revenue', msg(), ctx(), hits({ revenue: ['h1'] }))).toBe(false);
  });

  it('filename: only matches once the index answers', () => {
    expect(q('filename:*.pdf')).toBe(false);
    expect(q('filename:*.pdf', msg(), ctx(), hits({}, { '*.pdf': ['h1'] }))).toBe(true);
  });

  it('a negated word excludes body matches too', () => {
    expect(q('-revenue', msg(), ctx(), hits({ revenue: ['h1'] }))).toBe(false);
    expect(q('-quarterly')).toBe(false);
  });
});
