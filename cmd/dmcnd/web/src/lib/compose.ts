// ComposeReplyTo is what the reader hands the composer to open a reply: the recipients a
// Reply or Reply All resolves to, the quoted original, and the threading metadata that keeps
// the exchange one thread.
//
// Its own module because three shared screens pass it around and only one of them opens the
// composer — a type is not a reason to depend on a component.
export interface ComposeReplyTo {
  // One or more recipients: a plain Reply carries just the sender; Reply All carries
  // the sender plus every other original recipient (see MessageReader.buildReply).
  to: string[];
  cc?: string[];
  // Raw subject; the "Re:" prefix is applied by the composer.
  subject: string;
  // Prebuilt Gmail-style quoted original, placed below the signature. `quote` is the
  // plain-text form; `quoteHtml` the HTML one (sanitized, cid: images dropped). The
  // composer picks whichever matches its current mode.
  quote?: string;
  quoteHtml?: string;
  // Threading metadata (hex): the original's messageId → header replyToId, and the
  // original's threadId → continue that thread. Empty/all-zero ⇒ start a fresh thread.
  replyToId?: string;
  threadId?: string;
}
