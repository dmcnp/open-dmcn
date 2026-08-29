// toPlainText renders HTML down to a text/plain rendering — the part that always
// accompanies it on the wire (MessageContent.body stays text/plain; the HTML rides in
// `alternatives`).
//
// This is what a text-only client, the trust-gated plain-text peek, and the header
// `snippet` all read — so it has to be a genuine rendering, not a tag strip.
//
// Two callers, deliberately: the composer runs it over ALREADY-SANITIZED html
// (sanitizeOutgoing, a narrow closed tag set), and the reader runs it over RECEIVED
// html when a bridged legacy message carries no text/plain part at all. The second is
// arbitrary third-party markup, so the tag handling below covers what real mail is built
// from — layout tables, and <style>/<script> whose text is markup, not message content.
// Nothing here inserts HTML: the DOM it parses is detached and inert (no scripts run, no
// resources load), and only text comes back out.

// Elements that start and end a line. Table rows and cells are included because HTML mail
// is overwhelmingly laid out in tables — without them a newsletter renders as one
// unbroken paragraph.
const BLOCK = new Set([
  'P', 'DIV', 'LI', 'UL', 'OL', 'BLOCKQUOTE', 'PRE', 'H1', 'H2', 'H3', 'HR',
  'H4', 'H5', 'H6', 'TABLE', 'TR', 'TD', 'TH', 'SECTION', 'ARTICLE', 'HEADER',
  'FOOTER', 'CENTER', 'ADDRESS', 'DT', 'DD',
]);

// Elements whose text content is not message content — dropping the element alone would
// spill CSS or script source into the rendering.
const SKIP = new Set(['SCRIPT', 'STYLE', 'HEAD', 'TITLE', 'NOSCRIPT', 'TEMPLATE', 'IFRAME', 'OBJECT', 'EMBED']);

interface Ctx {
  /** Inside <pre>: whitespace is significant and must not be collapsed. */
  pre: boolean;
}

// trimEdges strips spaces/tabs (never newlines) from both ends of a rendered block.
function trimEdges(text: string): string {
  return text.replace(/^[ \t]+/, '').replace(/[ \t]+$/, '');
}

// prefixLines prefixes every line of a block with `p` (used for blockquote's "> ").
function prefixLines(text: string, p: string): string {
  return text
    .split('\n')
    .map(l => (l ? p + l : p.trimEnd()))
    .join('\n');
}

function renderChildren(node: Node, ctx: Ctx): string {
  let out = '';
  for (const child of Array.from(node.childNodes)) out += render(child, ctx);
  return out;
}

function render(node: Node, ctx: Ctx): string {
  if (node.nodeType === 3 /* text */) {
    const raw = node.nodeValue ?? '';
    // Outside <pre>, HTML whitespace is insignificant: collapse runs to a single space so
    // the source's own indentation doesn't leak into the plain-text rendering.
    return ctx.pre ? raw : raw.replace(/\s+/g, ' ');
  }
  if (node.nodeType !== 1 /* element */) return '';

  const el = node as Element;
  if (SKIP.has(el.tagName)) return '';
  switch (el.tagName) {
    case 'BR':
      return '\n';
    case 'HR':
      return '\n---\n';
    case 'IMG': {
      // Only images carrying alt text say anything; HTML mail is full of spacer and
      // tracking pixels whose placeholders would be pure noise.
      const alt = el.getAttribute('alt')?.trim();
      return alt ? `[image: ${alt}]` : '';
    }
    case 'A': {
      const text = renderChildren(el, ctx).trim();
      const href = el.getAttribute('href')?.trim() ?? '';
      // Only spell out the URL when it adds something — a bare link already showing its
      // own URL, an in-page anchor, or a cid: reference would otherwise render as
      // "https://x <https://x>".
      const bare = href && !href.startsWith('#') && !href.startsWith('cid:') ? href : '';
      if (!href || href === text || !bare) return text || bare;
      return text ? `${text} <${href}>` : `<${href}>`;
    }
    case 'PRE':
      return '\n' + renderChildren(el, { ...ctx, pre: true }).replace(/^\n+|\n+$/g, '') + '\n';
    case 'BLOCKQUOTE': {
      const inner = renderChildren(el, ctx).replace(/^\n+|\n+$/g, '');
      return '\n' + prefixLines(inner, '> ') + '\n';
    }
    case 'UL':
    case 'OL': {
      // Number only the direct <li> children, so a nested list restarts at 1.
      const items = Array.from(el.children).filter(c => c.tagName === 'LI');
      const lines = items.map((li, i) => {
        const marker = el.tagName === 'OL' ? `${i + 1}. ` : '- ';
        const body = renderChildren(li, ctx).replace(/^\n+|\n+$/g, '').trim();
        // Continuation lines (a nested list, a <br>) align under the marker's text.
        return prefixLines(body, ' '.repeat(marker.length)).replace(/^ +/, marker);
      });
      return '\n' + lines.join('\n') + '\n';
    }
    default:
      // Trim the block's edge spaces: the source's own indentation after a tag collapses
      // to a leading space, which would otherwise indent every line of real mail by one.
      if (BLOCK.has(el.tagName)) return '\n' + trimEdges(renderChildren(el, ctx)) + '\n';
      return renderChildren(el, ctx);
  }
}

// toPlainText converts sanitized HTML into its text/plain rendering.
export function toPlainText(html: string): string {
  if (!html) return '';
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out = renderChildren(doc.body, { pre: false });
  return out
    .replace(/[ \t]+\n/g, '\n')   // strip trailing spaces the block boundaries leave behind
    .replace(/\n{3,}/g, '\n\n')   // at most one blank line between blocks
    .replace(/^\n+/, '')
    .replace(/\s+$/, '');
}
