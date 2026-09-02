import DOMPurify from 'dompurify';

// The single HTML allowlist for the mail client — shared by the reader (what we RENDER)
// and the composer (what we SEND). Keeping both directions in one module means a tag can
// never be permitted on one side and forgotten on the other.
//
// Two directions, deliberately different shapes:
//   - sanitizeIncoming: a denylist over DOMPurify's defaults, because received mail is
//     arbitrary third-party markup we still want to render faithfully. It is only ever
//     rendered inside the sandboxed, CSP-locked iframe in HtmlMessageBody.
//   - sanitizeOutgoing: a positive allowlist, because we control what we emit and a
//     narrow tag set is what renders consistently across legacy mail clients. It also
//     runs on PASTED markup, so a malicious page copied into the composer can't turn the
//     sender into the attack vector.
//
// Outgoing NEVER permits a remote resource reference. Incoming blocks them by default and
// admits exactly one, exactly on request: an absolute https: <img> src, when the reader has
// opted in (Settings) AND the sender is one they trust. Nothing else — no scripts, frames,
// fonts, media or stylesheets — is ever fetched, and the iframe CSP in HtmlMessageBody
// enforces that independently of what this module lets through.

// Tags that carry active/remote/interactive surface — dropped even though DOMPurify
// neutralizes most by default (belt-and-suspenders; the reader's sandbox also blocks them).
const FORBID_TAGS = ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'textarea', 'select', 'link', 'base', 'meta', 'title', 'svg', 'math', 'noscript'];
const FORBID_ATTR = ['srcset', 'ping', 'formaction'];

// What the composer is allowed to EMIT. Deliberately narrow: the tags below are the
// intersection of what the toolbar produces and what legacy mail clients render
// predictably. No style/class — the reader's iframe stylesheet governs presentation, so
// outgoing mail can't smuggle layout tricks (or a CSS-based tracker) either.
const OUTGOING_TAGS = ['p', 'br', 'div', 'span', 'b', 'strong', 'i', 'em', 'u', 's', 'a', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'h1', 'h2', 'h3', 'hr', 'img'];
const OUTGOING_ATTR = ['href', 'src', 'alt', 'title'];

export interface SanitizeResult {
  html: string;
  /** A remote resource reference was found and removed. */
  blockedRemote: boolean;
}

export interface SanitizeIncomingOptions {
  /**
   * Let absolute https: <img> sources through instead of stripping them. The caller must
   * gate this on BOTH the reader's opt-in and a sender they trust — this module does not
   * know either, and will honour whatever it is handed.
   */
  allowRemoteImages?: boolean;
}

// ImageSrcVerdict is what an <img src> resolves to. 'blocked' is a reference we removed;
// 'empty' is an <img> that carried no source to begin with (nothing to report).
export type ImageSrcVerdict =
  | { kind: 'inline'; cid: string } // cid: → resolve against the message's own attachments
  | { kind: 'keep' }                // already-embedded data: image, no network involved
  | { kind: 'remote'; url: string } // absolute https:, kept only when allowed
  | { kind: 'blocked' }
  | { kind: 'empty' };

// classifyImageSrc is the whole remote-content decision, deliberately extracted as pure
// string logic: which URLs may reach the network is the security-critical part, and here it
// is testable without a DOM.
//
// http: is NOT upgraded to https:. A cleartext fetch would announce to every hop on the path
// that this message was opened — the exact leak the block exists to prevent — so an insecure
// image stays blocked even for a trusted sender (the iframe CSP refuses it independently).
// Relative paths resolve against the app origin rather than the sender's, so they can never
// be the image the sender meant; they are dropped too.
export function classifyImageSrc(src: string): ImageSrcVerdict {
  const raw = (src || '').trim();
  if (!raw) return { kind: 'empty' };
  if (/^cid:/i.test(raw)) return { kind: 'inline', cid: raw.slice(4) };
  if (/^data:image\//i.test(raw)) return { kind: 'keep' };
  // Protocol-relative (//host/path) would inherit the app's https — it is a remote fetch in
  // every case that matters, so name the scheme explicitly rather than letting it be implied.
  if (raw.startsWith('//')) return { kind: 'remote', url: 'https:' + raw };
  if (/^https:\/\//i.test(raw)) return { kind: 'remote', url: raw };
  return { kind: 'blocked' };
}

// withHook runs fn with a DOMPurify afterSanitizeAttributes hook installed, always
// removing it afterwards — DOMPurify hooks are global, so a leaked hook would silently
// apply to every other sanitize call in the app.
function withHook<T>(hook: (node: Element) => void, fn: () => T): T {
  DOMPurify.addHook('afterSanitizeAttributes', hook as (node: Node) => void);
  try {
    return fn();
  } finally {
    DOMPurify.removeHook('afterSanitizeAttributes');
  }
}

// sanitizeIncoming cleans RECEIVED HTML and rewrites resource references: cid: images →
// embedded data: URIs from the message's own inline attachments; remote images → removed by
// default (no IP leak / tracking pixels) or kept when opts.allowRemoteImages says the reader
// asked for them; links → open externally with no referrer. Reports only what it BLOCKED: a
// kept image needs no per-message remark, because what that costs is explained once, at the
// setting that permits it.
export function sanitizeIncoming(
  raw: string,
  inline: Map<string, string>,
  opts: SanitizeIncomingOptions = {}
): SanitizeResult {
  const allowRemote = opts.allowRemoteImages === true;
  let blockedRemote = false;
  const hook = (node: Element) => {
    if (node.tagName === 'IMG') {
      node.removeAttribute('srcset');
      const v = classifyImageSrc(node.getAttribute('src') || '');
      switch (v.kind) {
        case 'inline': {
          const uri = inline.get(v.cid);
          if (uri) node.setAttribute('src', uri);
          else node.removeAttribute('src');
          break;
        }
        case 'remote':
          if (allowRemote) {
            node.setAttribute('src', v.url);
          } else {
            node.removeAttribute('src');
            blockedRemote = true;
          }
          break;
        case 'blocked':
          node.removeAttribute('src');
          blockedRemote = true;
          break;
        case 'keep':
        case 'empty':
          break;
      }
    }
    if (node.tagName === 'A') {
      node.setAttribute('target', '_blank');
      node.setAttribute('rel', 'noopener noreferrer nofollow');
    }
  };
  const html = withHook(hook, () =>
    String(DOMPurify.sanitize(raw, { FORBID_TAGS, FORBID_ATTR, ALLOW_DATA_ATTR: false, WHOLE_DOCUMENT: false }))
  );
  return { html, blockedRemote };
}

// sanitizeOutgoing cleans HTML we are about to SEND (composer content and pasted markup).
// Only cid: image references survive — an <img> pointing at a remote URL is dropped rather
// than forwarded, so we never ship a tracking pixel on the sender's behalf or emit mail
// that renders as a broken image behind the recipient's remote-content block. Links keep
// their href (DOMPurify already rejects javascript:/data: URIs) but lose target/rel, which
// are the reader's business, not the wire's.
export function sanitizeOutgoing(raw: string): SanitizeResult {
  let blockedRemote = false;
  const hook = (node: Element) => {
    if (node.tagName === 'IMG') {
      const src = node.getAttribute('src') || '';
      if (!src.startsWith('cid:')) {
        node.remove();
        if (src) blockedRemote = true;
      }
    }
    if (node.tagName === 'A') {
      node.removeAttribute('target');
      node.removeAttribute('rel');
    }
  };
  const html = withHook(hook, () =>
    String(
      DOMPurify.sanitize(raw, {
        ALLOWED_TAGS: OUTGOING_TAGS,
        ALLOWED_ATTR: OUTGOING_ATTR,
        FORBID_TAGS,
        FORBID_ATTR,
        ALLOW_DATA_ATTR: false,
        WHOLE_DOCUMENT: false,
      })
    )
  );
  return { html, blockedRemote };
}
