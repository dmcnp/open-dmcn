import { useEffect, useImperativeHandle, useRef, useState, forwardRef, type CSSProperties, type ClipboardEvent, type DragEvent, type KeyboardEvent } from 'react';
import { IconButton, Input } from '../ds';
import { Icon } from './Icon';
import { sanitizeOutgoing } from '../lib/html/sanitize';
import { escapeHtml } from '../lib/html/fromPlainText';

// RichTextEditor is the composer's HTML surface: a contentEditable div plus a toolbar.
//
// Hand-rolled on purpose. A schema-based editor (ProseMirror/Lexical) would be a large
// new dependency in the origin that holds the user's keys, which is exactly what this
// codebase avoids; the formatting set an email needs is small enough to drive with
// document.execCommand. execCommand is deprecated but implemented everywhere and needs no
// eval, so it stays inside the strict nonce CSP.
//
// Two invariants matter here:
//   1. The div is UNCONTROLLED. React must never rewrite innerHTML while the user types —
//      that destroys the caret. It is seeded once on mount and only re-seeded through the
//      imperative setHTML(), which the composer calls solely while the body is untouched.
//   2. Pasted markup is sanitized BEFORE it reaches the DOM (sanitizeOutgoing), so copying
//      from a hostile page can't plant active content in the sender's own outgoing mail.
//
// Inline images live as <img data-cid> with a data: URI src for on-screen preview; getHTML()
// rewrites them to the `cid:` reference that actually goes on the wire, against an inline
// attachment the composer holds.

export interface RichTextEditorHandle {
  /** The composed HTML, with inline images rewritten to their cid: references. */
  getHTML(): string;
  /** Replace the content wholesale (mode switch / late-arriving signature prefill). */
  setHTML(html: string): void;
  focus(caretAtStart?: boolean): void;
}

export interface InsertedImage {
  /** Bare Content-ID the body references as <img src="cid:…">. */
  contentId: string;
  /** data: URI used only for the in-editor preview (CSP allows data:, not blob:). */
  previewUrl: string;
  /** Shown as the img alt, and as "[image: …]" in the plain-text alternative. */
  alt: string;
}

export interface RichTextEditorProps {
  initialHtml: string;
  placeholder?: string;
  mobile?: boolean;
  /** Fired on the first edit, so the composer stops applying prefills. */
  onDirty?: () => void;
  /** Accepts an image chosen/pasted/dropped into the body; null rejects it (e.g. over the size cap). */
  onInsertImage?: (file: File) => Promise<InsertedImage | null>;
  style?: CSSProperties;
}

// Commands whose on/off state the toolbar reflects.
const STATE_COMMANDS = ['bold', 'italic', 'underline', 'insertUnorderedList', 'insertOrderedList'] as const;

export const RichTextEditor = forwardRef<RichTextEditorHandle, RichTextEditorProps>(function RichTextEditor(
  { initialHtml, placeholder, mobile, onDirty, onInsertImage, style },
  ref
) {
  const elRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const dirtyRef = useRef(false);
  // Shift held during paste ⇒ paste as unformatted text. ClipboardEvent carries no
  // modifier state, so track it from the key events instead.
  const shiftRef = useRef(false);
  // Selection captured before focus moves into the link input, so createLink can be
  // applied to the range the user actually had selected.
  const savedRange = useRef<Range | null>(null);
  const [active, setActive] = useState<Record<string, boolean>>({});
  const [linkOpen, setLinkOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState('');

  // Seed once. Deliberately NOT keyed on initialHtml — see the uncontrolled invariant.
  useEffect(() => {
    if (elRef.current) elRef.current.innerHTML = initialHtml;
    // Emit <b>/<i> tags rather than style-carrying spans: cleaner mail HTML, and it
    // survives the outgoing allowlist (which drops style attributes).
    try { document.execCommand('styleWithCSS', false, 'false'); } catch { /* not supported; tags are the default anyway */ }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const syncActive = () => {
    const next: Record<string, boolean> = {};
    for (const c of STATE_COMMANDS) {
      try { next[c] = document.queryCommandState(c); } catch { next[c] = false; }
    }
    setActive(next);
  };

  // Track the toolbar's on/off state, but only while the selection is inside this editor.
  useEffect(() => {
    const onSelChange = () => {
      const el = elRef.current;
      const sel = document.getSelection();
      if (!el || !sel || sel.rangeCount === 0) return;
      if (el.contains(sel.anchorNode)) syncActive();
    };
    document.addEventListener('selectionchange', onSelChange);
    return () => document.removeEventListener('selectionchange', onSelChange);
  }, []);

  const markDirty = () => {
    if (dirtyRef.current) return;
    dirtyRef.current = true;
    onDirty?.();
  };

  useImperativeHandle(ref, () => ({
    getHTML() {
      const el = elRef.current;
      if (!el) return '';
      // Work on a clone so the visible editor keeps its previewable data: URIs.
      const clone = el.cloneNode(true) as HTMLElement;
      for (const img of Array.from(clone.querySelectorAll('img[data-cid]'))) {
        img.setAttribute('src', `cid:${img.getAttribute('data-cid')}`);
        img.removeAttribute('data-cid');
      }
      return clone.innerHTML;
    },
    setHTML(html: string) {
      if (elRef.current) elRef.current.innerHTML = html;
      dirtyRef.current = false;
    },
    focus(caretAtStart?: boolean) {
      const el = elRef.current;
      if (!el) return;
      el.focus();
      if (!caretAtStart) return;
      const range = document.createRange();
      range.setStart(el, 0);
      range.collapse(true);
      const sel = document.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    },
  }));

  // exec runs a command against the editor's own selection and refreshes the toolbar.
  const exec = (cmd: string, value?: string) => {
    elRef.current?.focus();
    try { document.execCommand(cmd, false, value); } catch { /* unsupported command — leave content untouched */ }
    markDirty();
    syncActive();
  };

  const insertImages = async (files: File[]) => {
    if (!onInsertImage) return;
    for (const f of files) {
      const inserted = await onInsertImage(f);
      if (!inserted) continue;
      exec(
        'insertHTML',
        `<img src="${escapeHtml(inserted.previewUrl)}" data-cid="${escapeHtml(inserted.contentId)}" alt="${escapeHtml(inserted.alt)}">`
      );
    }
  };

  const handlePaste = (e: ClipboardEvent<HTMLDivElement>) => {
    const dt = e.clipboardData;
    if (!dt) return;

    const images = Array.from(dt.files).filter(f => f.type.startsWith('image/'));
    if (images.length && onInsertImage) {
      e.preventDefault();
      void insertImages(images);
      return;
    }

    // Shift+paste, or a clipboard with no markup: insert the text, escaped.
    const html = shiftRef.current ? '' : dt.getData('text/html');
    if (!html) {
      const text = dt.getData('text/plain');
      if (!text) return;
      e.preventDefault();
      exec('insertHTML', escapeHtml(text).replace(/\r?\n/g, '<br>'));
      return;
    }

    // Sanitize BEFORE insertion — raw clipboard markup never touches the live DOM.
    e.preventDefault();
    exec('insertHTML', sanitizeOutgoing(html).html);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    const images = Array.from(e.dataTransfer?.files ?? []).filter(f => f.type.startsWith('image/'));
    if (!images.length || !onInsertImage) return;
    e.preventDefault();
    void insertImages(images);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Shift') shiftRef.current = true;
    if (!(e.metaKey || e.ctrlKey)) return;
    const k = e.key.toLowerCase();
    // The browser already maps Cmd/Ctrl+B/I/U inside contentEditable; intercept only the
    // link shortcut, which has no native binding.
    if (k === 'k') { e.preventDefault(); openLink(); }
  };

  const openLink = () => {
    const sel = document.getSelection();
    savedRange.current = sel && sel.rangeCount > 0 ? sel.getRangeAt(0).cloneRange() : null;
    setLinkUrl('');
    setLinkOpen(true);
  };

  const applyLink = () => {
    const url = linkUrl.trim();
    setLinkOpen(false);
    if (!url) return;
    // Restore the pre-input selection so createLink wraps what the user had highlighted.
    const range = savedRange.current;
    elRef.current?.focus();
    if (range) {
      const sel = document.getSelection();
      sel?.removeAllRanges();
      sel?.addRange(range);
    }
    // Default to https:// so a bare "example.com" doesn't become a relative link. Any
    // scheme DOMPurify rejects (javascript:, data:) is dropped by sanitizeOutgoing on send.
    const href = /^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('mailto:') ? url : `https://${url}`;
    if (range && !range.collapsed) exec('createLink', href);
    else exec('insertHTML', `<a href="${escapeHtml(href)}">${escapeHtml(url)}</a>`);
  };

  const tool = (name: string, label: string, cmd: string, value?: string) => (
    <IconButton
      size="sm"
      aria-label={label}
      title={label}
      active={!!active[cmd]}
      onMouseDown={e => e.preventDefault()} // keep the editor's selection while clicking
      onClick={() => exec(cmd, value)}
    >
      <Icon name={name} size={15} />
    </IconButton>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0, ...style }}>
      <div
        role="toolbar"
        aria-label="Formatting"
        style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-1)', padding: 'var(--space-2) var(--space-3)', borderBottom: '1px solid var(--border-subtle)' }}
      >
        {tool('bold', 'Bold', 'bold')}
        {tool('italic', 'Italic', 'italic')}
        {tool('underline', 'Underline', 'underline')}
        <span style={{ width: 1, alignSelf: 'stretch', background: 'var(--border-subtle)', margin: '0 var(--space-1)' }} />
        {tool('list', 'Bulleted list', 'insertUnorderedList')}
        {tool('list-ordered', 'Numbered list', 'insertOrderedList')}
        {tool('quote', 'Quote', 'formatBlock', 'blockquote')}
        {tool('code', 'Code block', 'formatBlock', 'pre')}
        <span style={{ width: 1, alignSelf: 'stretch', background: 'var(--border-subtle)', margin: '0 var(--space-1)' }} />
        <IconButton size="sm" aria-label="Link" title="Link (⌘K)" onMouseDown={e => e.preventDefault()} onClick={openLink}>
          <Icon name="link" size={15} />
        </IconButton>
        {onInsertImage && (
          <IconButton size="sm" aria-label="Insert image" title="Insert image" onMouseDown={e => e.preventDefault()} onClick={() => fileRef.current?.click()}>
            <Icon name="image" size={15} />
          </IconButton>
        )}
        {tool('remove-formatting', 'Clear formatting', 'removeFormat')}
      </div>

      {linkOpen && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-2) var(--space-3)', borderBottom: '1px solid var(--border-subtle)', background: 'var(--surface-sunken)' }}>
          {/* Input renders a wrapper div, so the flex sizing belongs on the wrapper. */}
          <div style={{ flex: 1 }}>
            <Input
              autoFocus
              value={linkUrl}
              onChange={e => setLinkUrl(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') { e.preventDefault(); applyLink(); }
                if (e.key === 'Escape') { e.preventDefault(); setLinkOpen(false); }
              }}
              placeholder="https://example.com"
              aria-label="Link address"
            />
          </div>
          <IconButton size="sm" aria-label="Apply link" title="Apply link" onClick={applyLink}>
            <Icon name="check" size={15} />
          </IconButton>
          <IconButton size="sm" aria-label="Cancel link" title="Cancel" onClick={() => setLinkOpen(false)}>
            <Icon name="x" size={15} />
          </IconButton>
        </div>
      )}

      <div
        ref={elRef}
        className="dmcn-editor"
        contentEditable
        suppressContentEditableWarning
        role="textbox"
        aria-multiline="true"
        aria-label="Message body"
        data-placeholder={placeholder ?? ''}
        spellCheck
        onInput={markDirty}
        onPaste={handlePaste}
        onDrop={handleDrop}
        onKeyDown={handleKeyDown}
        onKeyUp={e => { if (e.key === 'Shift') shiftRef.current = false; }}
        onBlur={() => { shiftRef.current = false; }}
        style={{
          flex: 1,
          overflowY: 'auto',
          fontSize: mobile ? 16 : 'var(--text-base)',
          lineHeight: 'var(--leading-relaxed)',
          color: 'var(--text-body)',
          padding: 'var(--space-4)',
          minHeight: mobile ? 0 : 200,
        }}
      />

      {onInsertImage && (
        <input
          ref={fileRef}
          type="file"
          accept="image/*"
          multiple
          style={{ display: 'none' }}
          onChange={e => { void insertImages(Array.from(e.target.files ?? [])); e.target.value = ''; }}
        />
      )}
    </div>
  );
});
