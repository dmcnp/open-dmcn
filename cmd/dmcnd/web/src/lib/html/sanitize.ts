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
// Neither direction ever permits a remote resource reference.

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
  /** A remote (http/https/protocol-relative) resource reference was found and removed. */
  blockedRemote: boolean;
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
// embedded data: URIs from the message's own inline attachments; remote images → removed
// (no IP leak / tracking pixels); links → open externally with no referrer. Returns
// whether any remote resource was blocked (for the UI notice).
export function sanitizeIncoming(raw: string, inline: Map<string, string>): SanitizeResult {
  let blockedRemote = false;
  const hook = (node: Element) => {
    if (node.tagName === 'IMG') {
      node.removeAttribute('srcset');
      const src = node.getAttribute('src') || '';
      if (src.startsWith('cid:')) {
        const uri = inline.get(src.slice(4));
        if (uri) node.setAttribute('src', uri);
        else node.removeAttribute('src');
      } else if (/^data:image\//i.test(src)) {
        // keep an already-embedded image
      } else if (src) {
        node.removeAttribute('src');
        blockedRemote = true;
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
