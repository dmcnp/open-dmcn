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
// to embedded data: URIs; remote images are stripped (no IP leak / tracking pixels).

// Inner-iframe CSP: no scripts, connections, frames, media, or remote fonts; only
// embedded data: images and inline styles. Remote loads (incl. CSS url()) are blocked
// here regardless of what the sanitizer let through.
const INNER_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:";

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
}

export function HtmlMessageBody({ html, attachments }: HtmlMessageBodyProps) {
  const { doc, blockedRemote } = useMemo(() => {
    const inline = buildInlineMap(attachments);
    const { html: clean, blockedRemote } = sanitizeIncoming(html, inline);
    const shell =
      '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      `<meta http-equiv="Content-Security-Policy" content="${INNER_CSP}">` +
      '<base target="_blank">' +
      '<style>html,body{margin:0;padding:12px;font:14px/1.5 system-ui,-apple-system,sans-serif;color:#111;background:#fff;word-break:break-word;overflow-wrap:anywhere}img{max-width:100%;height:auto}a{color:#0b5fff}</style>' +
      `</head><body>${clean}</body></html>`;
    return { doc: shell, blockedRemote };
  }, [html, attachments]);

  return (
    <div style={{ marginTop: 'var(--space-6)' }}>
      {blockedRemote && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', background: 'var(--surface-sunken)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)', borderRadius: 'var(--radius-md)' }}>
          <Icon name="eye-off" size={15} style={{ flex: 'none' }} />
          <span>Remote images were blocked to protect your privacy.</span>
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
