// toPlainText renders composed HTML down to the text/plain part that always accompanies
// it on the wire (MessageContent.body stays text/plain; the HTML rides in `alternatives`).
//
// This is what a text-only client, the trust-gated plain-text peek, and the header
// `snippet` all read — so it has to be a genuine rendering, not a tag strip. It runs over
// ALREADY-SANITIZED html (sanitizeOutgoing), which is why the tag set it handles is small
// and closed.

// Elements that start and end a line.
const BLOCK = new Set(['P', 'DIV', 'LI', 'UL', 'OL', 'BLOCKQUOTE', 'PRE', 'H1', 'H2', 'H3', 'HR']);

interface Ctx {
  /** Inside <pre>: whitespace is significant and must not be collapsed. */
  pre: boolean;
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
  switch (el.tagName) {
    case 'BR':
      return '\n';
    case 'HR':
      return '\n---\n';
    case 'IMG': {
      const alt = el.getAttribute('alt')?.trim();
      return alt ? `[image: ${alt}]` : '[image]';
    }
    case 'A': {
      const text = renderChildren(el, ctx).trim();
      const href = el.getAttribute('href')?.trim() ?? '';
      // Only spell out the URL when the link text isn't already the URL — otherwise every
      // bare link would render as "https://x <https://x>".
      if (!href || href === text) return text || href;
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
      if (BLOCK.has(el.tagName)) return '\n' + renderChildren(el, ctx) + '\n';
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
