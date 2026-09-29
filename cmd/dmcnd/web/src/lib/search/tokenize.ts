// Turning text into the words the search index stores, and a query into the words it looks up.
//
// Both sides MUST go through the same function: the index is a set of folded tokens, and a query
// term only finds a token it was folded to match. So case, accents and compatibility forms are
// removed here once ("Café" → "cafe", "ﬁle" → "file"), and nowhere else.
//
// Word boundaries come from Intl.Segmenter where the platform has it, because a regular
// expression cannot find the words in Chinese or Japanese text, which is written without spaces.
// Inside each segment only letters and digits are kept, so punctuation never ends up in a token
// ("invoice-123" is "invoice" and "123", "o'brien" is "o" and "brien").

/** Text past this point in one message is not indexed. Mail longer than this is almost always a
 * pasted log or a forwarded thread, and the first 256 KB still covers what someone would search. */
export const MAX_INDEX_CHARS = 256 * 1024;
/** Longer "words" are base64, hashes and URLs: noise in an index, and never typed into a search. */
export const MAX_TOKEN = 40;

// Scripts written without spaces, where a single character is routinely a whole word. Everywhere
// else a one-character token is noise ("a", "I", the "s" of "it's") and is dropped.
const IDEOGRAPHIC = /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u;
const WORD = /[\p{L}\p{N}]+/gu;

// NFKD splits the accent off a letter so it can be dropped, and NFC afterwards puts back together
// what was decomposed but not dropped: Hangul syllables would otherwise stay as loose jamo.
export function fold(s: string): string {
  return s.normalize('NFKD').replace(/\p{M}+/gu, '').normalize('NFC').toLowerCase();
}

const segmenter: Intl.Segmenter | null =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl ? new Intl.Segmenter(undefined, { granularity: 'word' }) : null;

function keep(token: string): boolean {
  const n = [...token].length;
  if (n > MAX_TOKEN) return false;
  return n >= 2 || IDEOGRAPHIC.test(token);
}

/** Every distinct token in text, in first-seen order. */
export function tokenize(text: string): string[] {
  const folded = fold(text.length > MAX_INDEX_CHARS ? text.slice(0, MAX_INDEX_CHARS) : text);
  const out = new Set<string>();
  const take = (chunk: string) => {
    for (const m of chunk.matchAll(WORD)) if (keep(m[0])) out.add(m[0]);
  };
  if (segmenter) {
    for (const seg of segmenter.segment(folded)) if (seg.isWordLike) take(seg.segment);
  } else {
    take(folded);
  }
  return [...out];
}

/**
 * The shard a token lives in: its first two characters (one, for a one-character token).
 *
 * A query term is a PREFIX of the tokens it should find, and every token sharing a term's first
 * two characters is in one shard, so a term of two or more characters reads exactly one shard.
 */
export function shardOf(token: string): string {
  return [...token].slice(0, 2).join('');
}
