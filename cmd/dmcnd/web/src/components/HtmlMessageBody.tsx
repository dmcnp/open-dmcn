import { useMemo } from 'react';
import { toBase64 } from '../lib/crypto/keys';
import { sanitizeIncoming } from '../lib/html/sanitize';
import type { DecryptedAttachment } from '../lib/crypto/split';
import { Icon } from './Icon';

// HtmlMessageBody renders a received HTML mail part with defense-in-depth: it is
// (1) sanitized with DOMPurify, then (2) injected as the srcdoc of a SANDBOXED iframe
// with no allow-scripts / allow-same-origin, which (3) additionally carries its own
// locked-down CSP. So even a DOMPurify bypass can't run script, reach the app origin
// (which holds the keys), or load remote content. Inline (cid:) images are resolved
// to embedded data: URIs; remote images are stripped (no IP leak / tracking pixels)
// unless the reader has opted in for senders they trust (allowRemoteImages).

// innerCSP is the iframe's own policy: no scripts, connections, frames, media, or remote
// fonts, ever. Only the image source widens, and only when the reader asked for it.
//
// Widening img-src also admits CSS url() backgrounds, since CSP governs the fetch and not
// the tag that caused it. That is the honest shape of "load remote images": once a fetch to
// the sender's server is permitted at all, a stylesheet can make one just as an <img> can,
// and both tell the sender the same thing. The sanitizer still rewrites only <img> sources —
// the CSP is what actually decides, in both directions.
function innerCSP(allowRemoteImages: boolean): string {
  const img = allowRemoteImages ? 'data: https:' : 'data:';
  return `default-src 'none'; img-src ${img}; style-src 'unsafe-inline'; font-src data:`;
}

function buildInlineMap(attachments: DecryptedAttachment[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const a of attachments) {
    if (a.disposition === 'inline' && a.contentId) {
      m.set(a.contentId, `data:${a.contentType || 'application/octet-stream'};base64,${toBase64(a.content)}`);
    }
  }
  return m;
}

export interface HtmlMessageBodyProps {
  html: string;
  /** All decrypted attachments (inline ones resolve cid: references). */
  attachments: DecryptedAttachment[];
  /**
   * Allow images to be fetched from the sender's server. The caller owns this decision —
   * it must be both the reader's stored preference AND a sender they trust.
   */
  allowRemoteImages?: boolean;
}

export function HtmlMessageBody({ html, attachments, allowRemoteImages = false }: HtmlMessageBodyProps) {
  const { doc, blockedRemote } = useMemo(() => {
    const inline = buildInlineMap(attachments);
    const { html: clean, blockedRemote } = sanitizeIncoming(html, inline, { allowRemoteImages });
    const shell =
      '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      `<meta http-equiv="Content-Security-Policy" content="${innerCSP(allowRemoteImages)}">` +
      // A remote image request must never carry where it was opened from. The iframe's own
      // referrerPolicy covers the document load; this covers the subresources inside it.
      '<meta name="referrer" content="no-referrer">' +
      '<base target="_blank">' +
      '<style>html,body{margin:0;padding:12px;font:14px/1.5 system-ui,-apple-system,sans-serif;color:#111;background:#fff;word-break:break-word;overflow-wrap:anywhere}img{max-width:100%;height:auto}a{color:#0b5fff}</style>' +
      `</head><body>${clean}</body></html>`;
    return { doc: shell, blockedRemote };
  }, [html, attachments, allowRemoteImages]);

  return (
    <div style={{ marginTop: 'var(--space-6)' }}>
      {blockedRemote && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-sunken)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
          <Icon name="eye-off" size={15} style={{ flex: 'none' }} />
          <span>
            {allowRemoteImages
              ? 'Some images were blocked because they load over an insecure connection.'
              : 'Remote images were blocked to protect your privacy.'}
          </span>
        </div>
      )}
      {/* Sandboxed: NO allow-scripts, NO allow-same-origin. allow-popups(+escape) only so
          links open in a normal new tab. referrerPolicy hides the URL from link targets. */}
      <iframe
        title="Message content"
        srcDoc={doc}
        sandbox="allow-popups allow-popups-to-escape-sandbox"
        referrerPolicy="no-referrer"
        style={{ width: '100%', height: 600, border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)', background: '#fff' }}
      />
    </div>
  );
}
