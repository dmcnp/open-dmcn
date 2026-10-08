import { describe, expect, it } from 'vitest';
import type { Preview } from '../api/mailboxRest';
import { base64Lines, clean, encodeWords, exportMessageId, filenameParam, originalMessageId, quotedPrintable, renderMessage, rfc5322Date, withoutOwnHeaders, type ExportItem } from './mime';

const dec = new TextDecoder();
const enc = new TextEncoder();

const MID = '0123456789abcdef0123456789abcdef';
const THREAD = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const PARENT = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

function row(over: Partial<Preview> = {}): Preview {
  return {
    hash: 'h1', messageId: MID, threadId: '', senderAddress: 'alice@dmcn.email', senderPublicKey: 'ab'.repeat(32),
    recipientAddress: 'bob@dmcn.email', to: ['bob@dmcn.email'], cc: [], bcc: [], subject: 'Hello', snippet: '',
    senderDisplay: '', sentAt: 1_791_000_000, bodySize: 0, attachmentCount: 0, ...over,
  };
}

function item(over: Partial<ExportItem> = {}): ExportItem {
  return { row: row(), replyToId: '', text: 'Hi Bob', attachments: [], sent: false, ...over };
}

// The chunks a message is rendered in, joined: what the file holds.
const flat = (chunks: Uint8Array[]) => new Uint8Array(chunks.flatMap(c => Array.from(c)));
const render = (it: ExportItem) => dec.decode(flat(renderMessage(it, (() => { let n = 0; return () => `B${++n}`; })())));
const headersOf = (msg: string) => msg.slice(0, msg.indexOf('\r\n\r\n'));

// Undo quoted-printable, for checking what a reader would get back.
function unQP(s: string): string {
  const bytes: number[] = [];
  const body = s.replace(/=\r\n/g, '');
  for (let i = 0; i < body.length; i++) {
    if (body[i] === '=') { bytes.push(parseInt(body.slice(i + 1, i + 3), 16)); i += 2; } else bytes.push(body.charCodeAt(i));
  }
  return dec.decode(new Uint8Array(bytes));
}

describe('renderMessage, native mail', () => {
  it('writes a plain message as a single text part with the envelope headers', () => {
    const msg = render(item());
    const h = headersOf(msg);
    expect(h).toContain('From: alice@dmcn.email');
    expect(h).toContain('To: bob@dmcn.email');
    expect(h).toContain('Subject: Hello');
    expect(h).toContain(`Date: ${rfc5322Date(1_791_000_000)}`);
    expect(h).toContain(`Message-ID: <${MID}@dmcn.email>`);
    expect(h).toContain(`X-DMCN-Sender-Key: ${'ab'.repeat(32)}`);
    expect(h).toContain('Status: O');
    expect(h).toContain('MIME-Version: 1.0');
    expect(h).toContain('Content-Type: text/plain; charset=utf-8');
    expect(h).not.toMatch(/multipart|In-Reply-To|References|Bcc/);
    expect(msg.endsWith('\r\nHi Bob\r\n')).toBe(true);
  });

  it('threads a reply the way the bridge does: parent in In-Reply-To, thread root first in References', () => {
    const h = headersOf(render(item({ row: row({ threadId: THREAD }), replyToId: PARENT })));
    expect(h).toContain(`In-Reply-To: <${PARENT}@dmcn.email>`);
    expect(h).toContain(`References: <${THREAD}@dmcn.email> <${PARENT}@dmcn.email>`);
  });

  it('drops the thread anchor when there is none or it is the parent', () => {
    expect(headersOf(render(item({ replyToId: PARENT })))).toContain(`References: <${PARENT}@dmcn.email>\r\n`);
    expect(headersOf(render(item({ row: row({ threadId: PARENT }), replyToId: PARENT })))).toContain(`References: <${PARENT}@dmcn.email>\r\n`);
    expect(headersOf(render(item({ row: row({ threadId: '0'.repeat(32) }), replyToId: '0'.repeat(32) })))).not.toContain('In-Reply-To');
  });

  it('keeps Bcc on a Sent copy only, and falls back to the copy recipient when there is no list', () => {
    const bcc = row({ bcc: ['carol@dmcn.email'] });
    expect(headersOf(render(item({ row: bcc, sent: true })))).toContain('Bcc: carol@dmcn.email');
    expect(headersOf(render(item({ row: bcc, sent: false })))).not.toContain('Bcc');
    expect(headersOf(render(item({ row: row({ to: [] }) })))).toContain('To: bob@dmcn.email');
  });

  it('folds a long recipient list one address per line', () => {
    const h = headersOf(render(item({ row: row({ to: ['a@x.io', 'b@x.io', 'c@x.io'], cc: ['d@x.io'] }) })));
    expect(h).toContain('To: a@x.io,\r\n b@x.io,\r\n c@x.io');
    expect(h).toContain('Cc: d@x.io');
  });

  it('writes a display name quoted, and encoded when it is not ASCII', () => {
    expect(headersOf(render(item({ row: row({ senderDisplay: 'Alice "A" Smith' }) })))).toContain('From: "Alice \\"A\\" Smith" <alice@dmcn.email>');
    const h = headersOf(render(item({ row: row({ senderDisplay: 'Zoë' }) })));
    expect(h).toContain(`From: =?UTF-8?B?${Buffer.from('Zoë').toString('base64')}?= <alice@dmcn.email>`);
  });

  it('cannot be made to start a header of the sender’s choosing', () => {
    const h = headersOf(render(item({ row: row({ subject: 'hi\r\nBcc: eve@evil.example\r\n\r\nbody' }) })));
    expect(h.split('\r\n').filter(l => l.startsWith('Bcc'))).toEqual([]);
    expect(h).toContain('Subject: hi Bcc: eve@evil.example body');
  });

  it('writes text and HTML as multipart/alternative, text first', () => {
    const msg = render(item({ html: '<p>Hi Bob</p>' }));
    expect(headersOf(msg)).toContain('Content-Type: multipart/alternative; boundary="B1"');
    const text = msg.indexOf('Content-Type: text/plain');
    const html = msg.indexOf('Content-Type: text/html');
    expect(text).toBeGreaterThan(0);
    expect(html).toBeGreaterThan(text);
    expect(msg).toContain('<p>Hi Bob</p>');
    expect(msg.trimEnd().endsWith('--B1--')).toBe(true);
  });

  it('writes attachments into multipart/mixed after the body, inline ones with their Content-ID', () => {
    const msg = render(item({
      html: '<img src="cid:logo1">',
      attachments: [
        { filename: 'report.pdf', contentType: 'application/pdf', content: enc.encode('%PDF-1.7'), contentId: '', disposition: '' },
        { filename: 'logo.png', contentType: 'image/png', content: Uint8Array.of(1, 2, 3), contentId: 'logo1', disposition: 'inline' },
      ],
    }));
    expect(headersOf(msg)).toContain('Content-Type: multipart/mixed; boundary="B1"');
    expect(msg).toContain('Content-Type: multipart/alternative; boundary="B2"');
    expect(msg).toContain('Content-Disposition: attachment; filename="report.pdf"');
    expect(msg).toContain(`\r\n\r\n${Buffer.from('%PDF-1.7').toString('base64')}\r\n`);
    expect(msg).toContain('Content-Disposition: inline; filename="logo.png"');
    expect(msg).toContain('Content-ID: <logo1>');
    expect(msg.indexOf('--B2--')).toBeLessThan(msg.indexOf('report.pdf'));
    expect(msg.trimEnd().endsWith('--B1--')).toBe(true);
  });

  it('falls back to octet-stream for a content type it cannot write safely', () => {
    const msg = render(item({ attachments: [{ filename: 'x', contentType: 'text/plain\r\nX-Evil: 1', content: Uint8Array.of(0), contentId: '', disposition: '' }] }));
    expect(msg).toContain('Content-Type: application/octet-stream; name="x"');
    expect(msg).not.toContain('X-Evil');
  });

  it('writes the owner’s state as Status, X-Status, X-Keywords and the folder', () => {
    const h = headersOf(render(item({ read: true, starred: true, labels: ['Work', 'a,b'], place: 'Archive' })));
    expect(h).toContain('Status: RO');
    expect(h).toContain('X-Status: F');
    expect(h).toContain('X-Keywords: Work, a b');
    expect(h).toContain('X-DMCN-Folder: Archive');
    expect(headersOf(render(item({ sent: true })))).toContain('Status: RO');
  });

  it('names an alias copy’s address', () => {
    expect(headersOf(render(item({ row: row({ deliveredTo: 'shop@dmcn.email' }) })))).toContain('X-DMCN-Delivered-To: shop@dmcn.email');
  });
});

describe('renderMessage, bridged mail', () => {
  const original = Uint8Array.of(
    ...enc.encode('From: news@example.com\r\nDKIM-Signature: v=1; d=example.com\r\nSubject: x\r\n\r\n'),
    0xff, 0xfe, 0x0d, 0x0a, // not UTF-8: it must come through as it was
  );

  it('writes the original byte for byte under the check results', () => {
    const out = flat(renderMessage(item({
      original,
      bridge: { verified: true, spf: 'pass', dkim: 'pass', dmarc: 'fail' },
      read: true,
    })));
    const top = 'X-DMCN-Bridge-Checks: spf=pass; dkim=pass; dmarc=fail\r\nX-DMCN-Bridge-Verified: yes\r\nStatus: RO\r\n';
    expect(dec.decode(out.subarray(0, top.length))).toBe(top);
    expect(Array.from(out.subarray(top.length))).toEqual(Array.from(original));
  });

  it('says when the bridge’s account did not verify, and leaves off the bridge’s own key', () => {
    const msg = dec.decode(flat(renderMessage(item({ original, bridge: { verified: false, reason: 'untrusted bridge', spf: 'p@ss!' } }))));
    expect(msg).toContain('X-DMCN-Bridge-Checks: spf=pss; dkim=none; dmarc=none');
    expect(msg).toContain('X-DMCN-Bridge-Verified: no (untrusted bridge)');
    expect(msg).not.toContain('X-DMCN-Sender-Key');
    expect(dec.decode(flat(renderMessage(item({ original, bridge: null }))))).toContain('X-DMCN-Bridge-Verified: no (no record of the checks)');
  });

  it('takes out the header lines the export writes itself, so a sender cannot forge them', () => {
    const forged = enc.encode(
      'From: spoof@example.com\r\nX-DMCN-Bridge-Verified: yes\r\nX-DMCN-Bridge-Checks: spf=pass;\r\n dkim=pass; dmarc=pass\r\n'
      + 'status: RO\r\nX-Keywords: Paid\r\nSubject: Invoice\r\n\r\nX-DMCN-Bridge-Verified: yes in the body stays\r\n');
    const msg = dec.decode(flat(renderMessage(item({ original: forged, bridge: { verified: false, reason: 'dmarc failed' } }))));
    const head = msg.slice(0, msg.indexOf('\r\n\r\n'));
    expect(head.match(/X-DMCN-Bridge-Verified:.*/g)).toEqual(['X-DMCN-Bridge-Verified: no (dmarc failed)']);
    expect(head).not.toContain('dkim=pass');
    expect(head).not.toContain('X-Keywords');
    expect(head.match(/^status:/gim)).toEqual(['Status:']);
    expect(head).toContain('From: spoof@example.com\r\nSubject: Invoice');
    expect(msg).toContain('X-DMCN-Bridge-Verified: yes in the body stays');
  });

  it('leaves an original with none of those lines as the very same bytes', () => {
    expect(withoutOwnHeaders(original)).toEqual([original]);
  });

  it('writes the encoding of an attachment as its own chunk', () => {
    const big = new Uint8Array(3000);
    const chunks = renderMessage(item({ attachments: [{ filename: 'a.bin', contentType: 'application/octet-stream', content: big, contentId: '', disposition: '' }] }));
    expect(chunks.some(c => c.length === base64Lines(big).length)).toBe(true);
    for (const c of chunks.slice(0, -1)) expect(c.at(-1)).toBe(0x0a); // every chunk but the last ends a line
  });
});

describe('threading against the exported Message-IDs', () => {
  it('names a parent from another domain, or a bridged parent, the way the export wrote it', () => {
    const ids = new Map([
      [PARENT, exportMessageId(PARENT, 'bob@dmcn.me')],
      [THREAD, '<CAF00@mail.gmail.com>'],
    ]);
    const h = headersOf(render(item({ row: row({ threadId: THREAD }), replyToId: PARENT, ids })));
    expect(h).toContain(`In-Reply-To: <${PARENT}@dmcn.me>`);
    expect(h).toContain(`References: <CAF00@mail.gmail.com> <${PARENT}@dmcn.me>`);
  });

  it('reads the original’s own Message-ID, folded or not', () => {
    expect(originalMessageId(enc.encode('From: a@x\r\nMessage-ID: <abc@x.example>\r\n\r\nbody'))).toBe('<abc@x.example>');
    expect(originalMessageId(enc.encode('Message-Id:\r\n <folded@x.example>\r\nSubject: s\r\n\r\n'))).toBe('<folded@x.example>');
    expect(originalMessageId(enc.encode('Subject: s\r\n\r\nMessage-ID: <in-body@x>\r\n'))).toBeUndefined();
  });
});

describe('quotedPrintable', () => {
  it('round-trips text, UTF-8 and trailing whitespace', () => {
    const text = 'Grüße, Bob = 2\nline with trailing space \n\ttab';
    const qp = quotedPrintable(text);
    expect(qp).toContain('Gr=C3=BC=C3=9Fe');
    expect(qp).toContain('=3D');
    expect(qp).toContain('space=20\r\n');
    expect(unQP(qp)).toBe(text.replace(/\n/g, '\r\n') + '\r\n');
  });

  it('keeps every line within 76 characters', () => {
    const qp = quotedPrintable('x'.repeat(300) + '\n' + 'é'.repeat(100));
    for (const l of qp.split('\r\n')) expect(l.length).toBeLessThanOrEqual(76);
    expect(unQP(qp)).toBe('x'.repeat(300) + '\r\n' + 'é'.repeat(100) + '\r\n');
  });

  it('never leaves a line that reads "From " or starts with a dot', () => {
    const qp = quotedPrintable('From here\n.\nok');
    expect(qp).toBe('=46rom here\r\n=2E\r\nok\r\n');
  });

  it('guards a soft break’s continuation line the same way', () => {
    for (const lead of ['From the top', '.hidden']) {
      const qp = quotedPrintable('x'.repeat(75) + lead);
      const second = qp.split('=\r\n')[1];
      expect(second.startsWith('From ') || second.startsWith('.')).toBe(false);
      expect(unQP(qp)).toBe('x'.repeat(75) + lead + '\r\n');
    }
  });
});

describe('header helpers', () => {
  it('encodes non-ASCII as encoded words of at most 75 characters, split between characters', () => {
    expect(encodeWords('plain')).toBe('plain');
    const long = 'Пожалуйста, подтвердите ваш адрес электронной почты сегодня';
    const words = encodeWords(long).split('\r\n ');
    expect(words.length).toBeGreaterThan(1);
    for (const w of words) expect(w.length).toBeLessThanOrEqual(75);
    const back = words.map(w => Buffer.from(w.slice(10, -2), 'base64').toString('utf8')).join('');
    expect(back).toBe(long);
  });

  it('writes a non-ASCII filename as an RFC 2231 parameter', () => {
    expect(filenameParam('filename', 'a "b".txt')).toBe('filename="a \\"b\\".txt"');
    expect(filenameParam('filename', 'résumé.pdf')).toBe("filename*=UTF-8''r%C3%A9sum%C3%A9.pdf");
  });

  it('wraps base64 at 76 characters', () => {
    const lines = dec.decode(base64Lines(new Uint8Array(200))).split('\r\n');
    expect(lines[0].length).toBe(76);
    expect(lines.at(-1)).toBe('');
    // The same encoding as the platform's, at every padding length.
    for (const n of [0, 1, 2, 3, 56, 57, 58, 1000]) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
      expect(dec.decode(base64Lines(b)).replace(/\r\n/g, '')).toBe(Buffer.from(b).toString('base64'));
    }
  });

  it('dates in UTC, and cleans control characters from a header value', () => {
    expect(rfc5322Date(0)).toBe('Thu, 01 Jan 1970 00:00:00 +0000');
    expect(clean(' a\r\n\tb\u0000c ')).toBe('a \tb c');
  });
});
