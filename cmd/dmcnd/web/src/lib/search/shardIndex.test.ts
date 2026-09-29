import { describe, expect, it } from 'vitest';
import { addPosting, byShard, decodeShard, dropDocs, encodeShard, prefixDocs, type Shard } from './shardIndex';

describe('addPosting', () => {
  it('keeps posting lists ascending and free of duplicates', () => {
    const s: Shard = new Map();
    for (const d of [1, 5, 5, 3, 9, 0]) addPosting(s, 'invoice', d);
    expect(s.get('invoice')).toEqual([0, 1, 3, 5, 9]);
  });
});

describe('prefixDocs', () => {
  it('finds every doc holding a token the term starts', () => {
    const s: Shard = new Map([['invoice', [1, 2]], ['invite', [3]], ['index', [4]]]);
    expect([...prefixDocs(s, 'inv')].sort()).toEqual([1, 2, 3]);
    expect([...prefixDocs(s, 'invoice')].sort()).toEqual([1, 2]);
    expect(prefixDocs(s, 'invoices').size).toBe(0);
  });
});

describe('dropDocs', () => {
  it('removes dead postings and tokens left empty', () => {
    const s: Shard = new Map([['invoice', [1, 2]], ['invite', [2]]]);
    expect(dropDocs(s, d => d === 2)).toBe(2);
    expect([...s]).toEqual([['invoice', [1]]]);
  });
});

describe('byShard', () => {
  it('groups tokens by their first two characters', () => {
    expect([...byShard(['invoice', 'invite', 'order'])]).toEqual([['in', ['invoice', 'invite']], ['or', ['order']]]);
  });
});

describe('encodeShard / decodeShard', () => {
  it('round-trips, including large doc numbers and non-ASCII tokens', () => {
    const s: Shard = new Map([
      ['invoice', [0, 1, 127, 128, 300, 16384, 2 ** 31 + 5]],
      ['résumé', [7]],
      ['東京', [2, 3]],
    ]);
    expect(decodeShard(encodeShard(s))).toEqual(s);
  });

  it('stores dense posting lists in about a byte per doc', () => {
    const list = Array.from({ length: 10_000 }, (_, i) => i);
    const bytes = encodeShard(new Map([['the', list]]));
    expect(bytes.length).toBeLessThan(10_100);
  });

  it('rejects a truncated shard rather than returning half of one', () => {
    const bytes = encodeShard(new Map([['invoice', [1, 2, 3]]]));
    expect(() => decodeShard(bytes.slice(0, bytes.length - 2))).toThrow(/truncated/);
  });
});
