// One shard of the inverted index, and the byte form it is sealed in. Pure: no storage, no crypto.
//
// A shard maps each token to the ascending list of document numbers containing it. Document
// numbers are small integers handed out in order (indexStore's manifest maps them to message
// hashes), so a posting list is stored as deltas in LEB128 varints: a token found in most of a
// mailbox costs about a byte per message rather than a JSON number and a comma.

import { shardOf } from './tokenize';

export type Shard = Map<string, number[]>;

/** Record that doc contains token. Docs normally arrive in ascending order, so this appends. */
export function addPosting(shard: Shard, token: string, doc: number): void {
  const list = shard.get(token);
  if (!list) { shard.set(token, [doc]); return; }
  const last = list[list.length - 1];
  if (doc > last) { list.push(doc); return; }
  if (doc === last) return;
  // Out of order: only a hand-edited or partly flushed index can get here. Keep it sorted.
  let i = 0;
  while (i < list.length && list[i] < doc) i++;
  if (list[i] !== doc) list.splice(i, 0, doc);
}

/** Remove every posting whose doc is dead; drop tokens left with none. Returns how many went. */
export function dropDocs(shard: Shard, dead: (doc: number) => boolean): number {
  let removed = 0;
  for (const [token, list] of shard) {
    const kept = list.filter(d => !dead(d));
    removed += list.length - kept.length;
    if (kept.length === 0) shard.delete(token);
    else if (kept.length !== list.length) shard.set(token, kept);
  }
  return removed;
}

/** Every doc holding a token that starts with term. */
export function prefixDocs(shard: Shard, term: string): Set<number> {
  const out = new Set<number>();
  for (const [token, list] of shard) {
    if (token.startsWith(term)) for (const d of list) out.add(d);
  }
  return out;
}

/** A doc's tokens grouped by the shard each belongs in. */
export function byShard(tokens: string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const t of tokens) {
    const id = shardOf(t);
    const list = out.get(id);
    if (list) list.push(t); else out.set(id, [t]);
  }
  return out;
}

// --- byte form -----------------------------------------------------------------------------
//
// shard   = count(varint) entry*
// entry   = tokenLen(varint) tokenUtf8 postings(varint) delta(varint)*
//
// The first delta is the doc number itself; each after it is the gap from the one before.

class Writer {
  private buf = new Uint8Array(256);
  private n = 0;
  private grow(need: number) {
    if (this.n + need <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.n + need) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.n));
    this.buf = next;
  }
  varint(v: number) {
    this.grow(10);
    while (v >= 0x80) { this.buf[this.n++] = (v % 0x80) | 0x80; v = Math.floor(v / 0x80); }
    this.buf[this.n++] = v;
  }
  bytes(b: Uint8Array) {
    this.grow(b.length);
    this.buf.set(b, this.n);
    this.n += b.length;
  }
  done(): Uint8Array { return this.buf.slice(0, this.n); }
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export function encodeShard(shard: Shard): Uint8Array {
  const w = new Writer();
  w.varint(shard.size);
  for (const [token, list] of shard) {
    const t = enc.encode(token);
    w.varint(t.length);
    w.bytes(t);
    w.varint(list.length);
    let prev = 0;
    for (const d of list) { w.varint(d - prev); prev = d; }
  }
  return w.done();
}

export function decodeShard(b: Uint8Array): Shard {
  let i = 0;
  const varint = (): number => {
    let v = 0, mul = 1;
    for (;;) {
      if (i >= b.length) throw new Error('search shard: truncated');
      const byte = b[i++];
      v += (byte & 0x7f) * mul;
      if (byte < 0x80) return v;
      mul *= 0x80;
    }
  };
  const shard: Shard = new Map();
  const count = varint();
  for (let k = 0; k < count; k++) {
    const len = varint();
    if (i + len > b.length) throw new Error('search shard: truncated');
    const token = dec.decode(b.subarray(i, i + len));
    i += len;
    const n = varint();
    const list = new Array<number>(n);
    let prev = 0;
    for (let j = 0; j < n; j++) { prev += varint(); list[j] = prev; }
    shard.set(token, list);
  }
  return shard;
}
