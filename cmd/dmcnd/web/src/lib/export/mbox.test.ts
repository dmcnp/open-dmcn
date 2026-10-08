import { describe, expect, it } from 'vitest';
import { fromLine, mboxEntry } from './mbox';

const enc = new TextEncoder();
const dec = new TextDecoder();

// The chunks an entry is written in, joined: what lands in the file.
const flat = (chunks: Uint8Array[]) => new Uint8Array(chunks.flatMap(c => Array.from(c)));
const entry = (msg: Uint8Array | Uint8Array[]) => flat(mboxEntry('a@x', 0, Array.isArray(msg) ? msg : [msg]));

describe('fromLine', () => {
  it('writes the sender and an asctime date in UTC, with the day padded by a space', () => {
    expect(fromLine('alice@dmcn.email', Date.UTC(2026, 9, 8, 7, 5, 9) / 1000)).toBe('From alice@dmcn.email Thu Oct  8 07:05:09 2026');
    expect(fromLine('alice@dmcn.email', Date.UTC(2026, 9, 18) / 1000)).toBe('From alice@dmcn.email Sun Oct 18 00:00:00 2026');
  });

  it('never writes a space or control character into the sender', () => {
    expect(fromLine('a b\r\n@x', 0)).toBe('From ab@x Thu Jan  1 00:00:00 1970');
    expect(fromLine('', 0)).toBe('From MAILER-DAEMON Thu Jan  1 00:00:00 1970');
  });
});

describe('mboxEntry', () => {
  it('makes line ends LF and closes the message with a blank line', () => {
    const out = dec.decode(entry(enc.encode('Subject: s\r\n\r\nline one\r\nline two\r\n')));
    expect(out).toBe('From a@x Thu Jan  1 00:00:00 1970\nSubject: s\n\nline one\nline two\n\n');
  });

  it('ends an unterminated last line before the blank line', () => {
    expect(dec.decode(entry(enc.encode('a\r\nb')))).toBe('From a@x Thu Jan  1 00:00:00 1970\na\nb\n\n');
  });

  it('quotes "From " lines the mboxrd way, one more ">" each, and nothing else', () => {
    const body = 'From me\r\n>From you\r\n>>From them\r\nFromage\r\n From x\r\n>From\r\n';
    const out = dec.decode(entry(enc.encode(body))).split('\n').slice(1);
    expect(out).toEqual(['>From me', '>>From you', '>>>From them', 'Fromage', ' From x', '>From', '', '']);
  });

  it('keeps every byte that is not a line end, valid UTF-8 or not', () => {
    const msg = Uint8Array.of(0x41, 0xff, 0x0d, 0x42, 0x0d, 0x0a, 0x80);
    const out = entry(msg);
    const head = enc.encode('From a@x Thu Jan  1 00:00:00 1970\n').length;
    // A lone CR is not a line end and stays; CRLF becomes LF.
    expect(Array.from(out.subarray(head))).toEqual([0x41, 0xff, 0x0d, 0x42, 0x0a, 0x80, 0x0a, 0x0a]);
  });

  it('converts each chunk on its own, and quotes a "From " line that starts one', () => {
    const out = dec.decode(entry([enc.encode('Subject: s\r\n\r\n'), enc.encode('From here\r\nok\r\n')]));
    expect(out).toBe('From a@x Thu Jan  1 00:00:00 1970\nSubject: s\n\n>From here\nok\n\n');
  });

  it('joins a chunk that stops mid-line to the next, so a "From " split across them is still quoted', () => {
    const out = dec.decode(entry([enc.encode('a\r\nFr'), enc.encode('om x\r\nb\r\n')]));
    expect(out).toBe('From a@x Thu Jan  1 00:00:00 1970\na\n>From x\nb\n\n');
  });
});
