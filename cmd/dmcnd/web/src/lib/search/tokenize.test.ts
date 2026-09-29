import { describe, expect, it } from 'vitest';
import { MAX_INDEX_CHARS, fold, shardOf, tokenize } from './tokenize';

describe('fold', () => {
  it('drops case, accents and compatibility forms', () => {
    expect(fold('Café Crème')).toBe('cafe creme');
    expect(fold('ﬁle')).toBe('file');
    expect(fold('ÅNGSTRÖM')).toBe('angstrom');
  });

  it('keeps Hangul syllables whole', () => {
    expect(fold('한국어')).toBe('한국어');
  });
});

describe('tokenize', () => {
  it('splits on punctuation and keeps each word once', () => {
    expect(tokenize('Invoice-123 for the INVOICE, from o\'brien')).toEqual(['invoice', '123', 'for', 'the', 'from', 'brien']);
  });

  it('drops one-letter Latin words but keeps single ideographs', () => {
    expect(tokenize('a I x ok')).toEqual(['ok']);
    expect(tokenize('猫').length).toBeGreaterThan(0);
  });

  it('finds words in text written without spaces', () => {
    const tokens = tokenize('東京で会議があります');
    expect(tokens.length).toBeGreaterThan(1);
    expect(tokens.join('')).toContain('東京');
  });

  it('drops tokens longer than a word could be', () => {
    expect(tokenize(`short ${'x'.repeat(41)}`)).toEqual(['short']);
  });

  it('indexes only the first MAX_INDEX_CHARS of a message', () => {
    const text = 'a '.repeat(MAX_INDEX_CHARS / 2) + 'needle';
    expect(tokenize(text)).not.toContain('needle');
  });

  it('matches query and index the same way', () => {
    expect(tokenize('RÉSUMÉ')).toEqual(tokenize('resume'));
  });
});

describe('shardOf', () => {
  it('is the first two characters, by code point', () => {
    expect(shardOf('invoice')).toBe('in');
    expect(shardOf('猫')).toBe('猫');
    expect(shardOf('😀😃x')).toBe('😀😃');
  });
});
