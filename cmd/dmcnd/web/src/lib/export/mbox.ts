// The mbox file around the messages: mboxrd, the variant whose quoting can be undone exactly.
//
// Each message starts on a "From " separator line and ends with a blank line. A line of the
// message that already reads "From ", behind any number of ">", gains one more ">", so no reader
// takes it for the start of the next message and a reader that knows mboxrd takes it off again.
// Line ends are LF, which is what Thunderbird, Apple Mail, mutt and Dovecot write and read.
//
// All of it works on bytes: a bridged message is the email the bridge received, written as it
// came, and decoding it to a string would change it for any byte that is not valid UTF-8.

const enc = new TextEncoder();
const LF = 0x0a;
const CR = 0x0d;
const GT = 0x3e;
const FROM = enc.encode('From ');

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const two = (n: number) => String(n).padStart(2, '0');

/** fromLine is the separator before a message: the envelope sender and an asctime date, in UTC. */
export function fromLine(sender: string, sec: number): string {
  const d = new Date(sec * 1000);
  const who = sender.replace(/[^\x21-\x7e]/g, '') || 'MAILER-DAEMON';
  return `From ${who} ${DAYS[d.getUTCDay()]} ${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, ' ')} `
    + `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())} ${d.getUTCFullYear()}`;
}

/**
 * mboxEntry is one message as it sits in the file: the separator, the message with its line ends
 * made LF and its "From " lines quoted, and the blank line that closes it. The message comes in
 * the chunks renderMessage wrote it in and goes out the same way, each converted on its own, so a
 * large attachment is never joined to the rest of its message in one more copy.
 */
export function mboxEntry(sender: string, sec: number, message: Uint8Array[]): Uint8Array[] {
  const out: Uint8Array[] = [enc.encode(fromLine(sender, sec) + '\n')];
  for (const chunk of lineAligned(message)) out.push(mboxLines(chunk));
  out.push(Uint8Array.of(LF));
  return out;
}

// lineAligned joins any chunk that stops mid-line to the one after it, so every chunk starts at the
// start of a line: a "From " that straddled two chunks would otherwise go unquoted. renderMessage
// never does this; the join is the fallback that keeps it from mattering if it ever did.
function lineAligned(chunks: Uint8Array[]): Uint8Array[] {
  const out: Uint8Array[] = [];
  let carry: Uint8Array | null = null;
  for (const c of chunks) {
    const cur: Uint8Array = carry ? join(carry, c) : c;
    carry = null;
    if (cur.length && cur[cur.length - 1] !== LF) carry = cur;
    else if (cur.length) out.push(cur);
  }
  if (carry) out.push(carry);
  return out;
}

function join(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

// mboxLines converts one run of whole lines: CRLF to LF, and one more ">" on each "From " line.
function mboxLines(message: Uint8Array): Uint8Array {
  // Two passes over the lines, one to size the result and one to fill it: a large attachment is
  // hundreds of thousands of lines, and one allocation beats that many small ones.
  const lines: Array<[number, number]> = [];
  let size = 0;
  for (let start = 0; start < message.length;) {
    let end = message.indexOf(LF, start);
    const next = end < 0 ? message.length : end + 1;
    if (end < 0) end = message.length;
    else if (end > start && message[end - 1] === CR) end--;
    lines.push([start, end]);
    size += end - start + 1 + (quotedFrom(message, start, end) ? 1 : 0);
    start = next;
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const [s, e] of lines) {
    if (quotedFrom(message, s, e)) out[at++] = GT;
    out.set(message.subarray(s, e), at);
    at += e - s;
    out[at++] = LF;
  }
  return out;
}

// quotedFrom: the line [start, end) is ">"* followed by "From ".
function quotedFrom(b: Uint8Array, start: number, end: number): boolean {
  let i = start;
  while (i < end && b[i] === GT) i++;
  if (end - i < FROM.length) return false;
  for (let j = 0; j < FROM.length; j++) if (b[i + j] !== FROM[j]) return false;
  return true;
}
