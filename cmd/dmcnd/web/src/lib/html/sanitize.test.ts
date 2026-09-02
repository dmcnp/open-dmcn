// The remote-content decision, tested on its own.
//
// classifyImageSrc is the only place that decides which URLs in a received message may reach
// the network — the difference between "opening this mail told the sender nothing" and "it
// told them when, where and on what device". The rest of sanitizeIncoming is DOMPurify plus
// DOM plumbing and needs a browser; this does not, so it is checked here directly.
//
// The block itself is enforced twice over: even if this function were wrong, the iframe CSP in
// HtmlMessageBody refuses anything but data: images unless remote images are switched on.

import { describe, it, expect } from 'vitest';
import { classifyImageSrc } from './sanitize';

describe('classifyImageSrc', () => {
  it('resolves cid: references against the message\'s own attachments', () => {
    expect(classifyImageSrc('cid:logo@example')).toEqual({ kind: 'inline', cid: 'logo@example' });
    // RFC 2392 schemes are case-insensitive.
    expect(classifyImageSrc('CID:logo@example')).toEqual({ kind: 'inline', cid: 'logo@example' });
  });

  it('keeps an already-embedded data: image (no network involved)', () => {
    expect(classifyImageSrc('data:image/png;base64,AAAA')).toEqual({ kind: 'keep' });
    // A non-image data: URI is not an image and must not be treated as one.
    expect(classifyImageSrc('data:text/html,<b>x')).toEqual({ kind: 'blocked' });
  });

  it('reports absolute https: as remote, leaving the caller to allow or block it', () => {
    expect(classifyImageSrc('https://tracker.example/pixel.gif?id=1'))
      .toEqual({ kind: 'remote', url: 'https://tracker.example/pixel.gif?id=1' });
  });

  it('names the scheme on a protocol-relative URL rather than letting it be implied', () => {
    expect(classifyImageSrc('//tracker.example/p.gif'))
      .toEqual({ kind: 'remote', url: 'https://tracker.example/p.gif' });
  });

  it('blocks http: rather than upgrading it — a cleartext fetch leaks the read to every hop', () => {
    expect(classifyImageSrc('http://tracker.example/p.gif')).toEqual({ kind: 'blocked' });
  });

  it('blocks relative paths, which would resolve against the app origin, not the sender\'s', () => {
    expect(classifyImageSrc('/assets/p.gif')).toEqual({ kind: 'blocked' });
    expect(classifyImageSrc('p.gif')).toEqual({ kind: 'blocked' });
  });

  it('blocks active and exotic schemes', () => {
    expect(classifyImageSrc('javascript:alert(1)')).toEqual({ kind: 'blocked' });
    expect(classifyImageSrc('file:///etc/passwd')).toEqual({ kind: 'blocked' });
    expect(classifyImageSrc('blob:https://app.example/abc')).toEqual({ kind: 'blocked' });
  });

  it('does not let surrounding whitespace smuggle a scheme past the checks', () => {
    // The HTML parser strips this before fetching, so the classifier must see the same URL
    // the browser would — otherwise " http://…" reads as a relative path and is "blocked"
    // for the wrong reason, which stops being harmless the moment the shapes diverge.
    expect(classifyImageSrc('  https://tracker.example/p.gif  '))
      .toEqual({ kind: 'remote', url: 'https://tracker.example/p.gif' });
    expect(classifyImageSrc('\n\tcid:logo')).toEqual({ kind: 'inline', cid: 'logo' });
  });

  it('treats a missing source as nothing to report', () => {
    expect(classifyImageSrc('')).toEqual({ kind: 'empty' });
    expect(classifyImageSrc('   ')).toEqual({ kind: 'empty' });
  });
});
