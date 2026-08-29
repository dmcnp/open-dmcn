// Rendering rules for a message's sender display name (MessageHeader.sender_display).
//
// The name is signed — a relay cannot rewrite it — but it is ASSERTED, not verified: for
// bridged legacy mail it is whatever the From header said, and the From header is only as
// trustworthy as the bridge's SPF/DKIM/DMARC verdict. Display names are the oldest
// phishing surface in mail, so this module holds the two rules that keep one safe:
//
//   1. it is only ever shown NEXT TO the address, never in place of it (senderLabel
//      returns both, and every caller renders both);
//   2. nothing keys off it — trust, allowlist, block and pinning all use the address and
//      the key, exactly as before.
//
// The producer sanitizes before signing (Go message.SanitizeDisplayName). This repeats the
// cleanup at RENDER time because the producer is whoever signed the header, which is not
// necessarily us: a header that reaches this client with control characters or a
// bidi-override in its name was written by something that did not follow the rule, and the
// reader is the last place to catch it. Cleaning here (rather than at decode) leaves the
// signature-verified bytes untouched.

// Bidirectional formatting codepoints: invisible, and they reorder rendered text — the
// classic way to make a name read as something other than what it is.
const BIDI = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
// C0/C1 control characters, including the CR/LF that would turn a name into two lines.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/g;

// Matches the Go producer's cap, so a name that survived signing is not trimmed again here.
const MAX_LEN = 96;

// sanitizeDisplayName reduces a wire display name to a single line of printable text,
// or '' when nothing usable is left.
export function sanitizeDisplayName(raw: string | undefined): string {
  if (!raw) return '';
  const out = raw
    .replace(BIDI, '')
    // Whitespace collapses BEFORE the control strip, so a CR/LF becomes a space (as it
    // does in the Go producer) instead of gluing the words on either side of it together.
    .replace(/\s+/g, ' ')
    .replace(CONTROL, '')
    .trim()
    .slice(0, MAX_LEN);
  // A hard slice can cut a surrogate pair in half; drop the orphan rather than render �.
  return (/[\uD800-\uDBFF]$/.test(out) ? out.slice(0, -1) : out).trim();
}

// senderLabel resolves what to show for a counterparty, in priority order:
//
//   1. the name the OWNER gave the contact (contactName, from useContacts.nameFor);
//   2. the display name the message carried;
//   3. the address.
//
// `secondary` is the address whenever `primary` is a name — of either kind — and empty
// only when `primary` IS the address. So a caller that renders both never hides the
// identity behind a label, and one that has room for a single column (the list row) can
// render `primary` alone knowing the reader will show the address in full.
export function senderLabel(
  address: string,
  contactName: string,
  wireDisplay?: string,
): { primary: string; secondary: string } {
  const named = contactName && contactName.trim().toLowerCase() !== address.trim().toLowerCase();
  if (named) return { primary: contactName, secondary: address };
  const display = sanitizeDisplayName(wireDisplay);
  // A name that merely repeats the address adds nothing; one that carries an address of
  // its own ("PayPal Security <security@paypal.com>" as the NAME) is a spoof attempt.
  // The bridge already drops both; this is the client refusing to render one anyway.
  if (!display || display.includes('@') || display.toLowerCase() === address.trim().toLowerCase()) {
    return { primary: address, secondary: '' };
  }
  return { primary: display, secondary: address };
}
