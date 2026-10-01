import { useEffect, useId, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { Icon } from './Icon';
import type { MessageChecksView } from '../lib/trust/checks';

// The reader's checks strip: where the message came from, then four plain words with a tick or
// a cross, then — attached underneath — the one sentence a failed check earns. The words are
// lib/trust/checks.ts's; this file only draws them.
//
// Every word carries its explanation. It is shown under the strip rather than beside the word,
// spanning the strip's width, so a word near the right edge of a phone never pushes its tip off
// the screen. Hover, focus and tap all open it: a phone has no hover, and iOS does not focus a
// tapped button, so a tap opens it explicitly and a tap anywhere else closes it.

const STRIP_RADIUS = 8;

const sourceIcon: Record<MessageChecksView['source']['kind'], { name: 'mail' | 'shield-check'; color: string } | null> = {
  regular: { name: 'mail', color: 'var(--text-muted)' },
  dmcn: { name: 'shield-check', color: 'var(--trust-dmcn)' },
  contact: { name: 'shield-check', color: 'var(--trust-contact)' },
  own: null,
  receipt: { name: 'mail', color: 'var(--text-muted)' },
};

function noticeColors(tone: 'danger' | 'warning' | 'neutral'): { bg: string; border: string; icon: string } {
  switch (tone) {
    case 'danger': return { bg: 'var(--danger-subtle)', border: 'color-mix(in srgb, var(--danger) 40%, var(--surface-card))', icon: 'var(--danger)' };
    case 'warning': return { bg: 'var(--warning-subtle)', border: 'color-mix(in srgb, var(--warning) 40%, var(--surface-card))', icon: 'var(--warning)' };
    case 'neutral': return { bg: 'var(--surface-sunken)', border: 'var(--border-subtle)', icon: 'var(--text-muted)' };
  }
}

const wordButton: CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: 6, minHeight: 28, padding: 0,
  background: 'none', border: 0, font: 'inherit', fontSize: 'var(--text-md)', fontWeight: 600,
  color: 'var(--text-strong)', cursor: 'help',
};

/** Checks strip; `view` null while the verdict is still resolving. */
export function MessageChecks({ view }: { view: MessageChecksView | null }) {
  const [open, setOpen] = useState<number | null>(null);
  const stripRef = useRef<HTMLDivElement>(null);
  const tipBase = useId();

  // A tap outside closes a tip a tap opened (nothing blurs on iOS); Escape closes it anywhere.
  useEffect(() => {
    if (open === null) return;
    const onDown = (e: PointerEvent) => {
      if (!stripRef.current?.contains(e.target as Node)) setOpen(null);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(null); };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('pointerdown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);

  if (!view) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', minHeight: 54, boxSizing: 'border-box', padding: '12px 16px', border: '1px solid var(--border-subtle)', borderRadius: STRIP_RADIUS, background: 'var(--surface-card)', color: 'var(--text-muted)', fontSize: 'var(--text-sm)' }}>
        Checking the sender…
      </div>
    );
  }

  const notice = view.notice;
  const failed = view.checks.some(c => !c.ok);
  const nc = notice ? noticeColors(notice.tone) : null;
  // The strip takes the notice's colour when there is one, so the two read as one panel.
  const stripBorder = nc && notice?.tone !== 'neutral' ? nc.border : 'var(--border-subtle)';
  const stripBg = notice?.tone === 'danger' ? 'color-mix(in srgb, var(--danger-subtle) 45%, var(--surface-card))' : 'var(--surface-card)';
  const si = sourceIcon[view.source.kind];
  // Index -1 is the source label; 0.. are the checks.
  const items = [{ tip: view.source.tip }, ...view.checks];
  const shownTip = open !== null ? items[open + 1]?.tip : null;
  const bind = (i: number) => ({
    onMouseEnter: () => setOpen(i),
    onMouseLeave: () => setOpen(o => (o === i ? null : o)),
    onFocus: () => setOpen(i),
    onBlur: () => setOpen(o => (o === i ? null : o)),
    onClick: () => setOpen(i),
    'aria-describedby': `${tipBase}-${i + 1}`,
  });

  return (
    <div ref={stripRef} style={{ position: 'relative', display: 'flex', flexDirection: 'column' }} data-checks={failed ? 'failed' : 'passed'}>
      <div style={{
        display: 'flex', alignItems: 'center', columnGap: 22, rowGap: 6, flexWrap: 'wrap', padding: '12px 16px',
        border: `1px solid ${stripBorder}`, borderRadius: notice ? `${STRIP_RADIUS}px ${STRIP_RADIUS}px 0 0` : STRIP_RADIUS, background: stripBg,
      }}>
        <button type="button" {...bind(-1)} style={{ ...wordButton, gap: 7, fontSize: 'var(--text-sm)', fontWeight: 500 }}>
          {si && <Icon name={si.name} size={16} style={{ color: si.color, flex: 'none' }} />}
          {view.source.label}
        </button>
        <div aria-hidden="true" style={{ width: 1, height: 18, background: 'var(--border-default)' }} />
        {view.checks.map((c, i) => (
          <button key={c.word} type="button" {...bind(i)} aria-label={`${c.word}: ${c.ok ? 'passed' : 'failed'}`} style={wordButton}>
            {c.ok
              ? <Icon name="check" size={16} strokeWidth={2.8} style={{ color: 'var(--brand)' }} />
              : <Icon name="x" size={16} strokeWidth={2.8} style={{ color: 'var(--danger)' }} />}
            {c.word}
          </button>
        ))}
      </div>

      {notice && nc && (
        <div role={notice.tone === 'danger' ? 'alert' : undefined} style={{
          display: 'flex', alignItems: 'flex-start', gap: 10, padding: '12px 16px',
          border: `1px solid ${nc.border}`, borderTop: 0, borderRadius: `0 0 ${STRIP_RADIUS}px ${STRIP_RADIUS}px`,
          background: nc.bg, color: 'var(--text-body)', fontSize: 'var(--text-md)', lineHeight: 1.5,
        }}>
          <Icon name={notice.tone === 'neutral' ? 'info' : 'alert-triangle'} size={18} style={{ color: nc.icon, flex: 'none', marginTop: 1 }} />
          <span>{notice.text}</span>
        </div>
      )}

      {/* Screen readers get each word's explanation through aria-describedby; the floating box
          below is the sighted copy of the same text. */}
      <div hidden>
        {items.map((it, i) => <span key={i} id={`${tipBase}-${i}`}>{it.tip}</span>)}
      </div>
      {shownTip && (
        <div aria-hidden="true" style={{
          position: 'absolute', top: 'calc(100% + 6px)', left: 0, zIndex: 50, maxWidth: 'min(440px, 100%)', boxSizing: 'border-box',
          padding: '8px 12px', borderRadius: 'var(--radius-sm)', background: 'var(--text-strong)', color: 'var(--surface-card)',
          fontSize: 'var(--text-sm)', lineHeight: 1.45, boxShadow: 'var(--shadow-md)', pointerEvents: 'none',
        }}>
          {shownTip}
        </div>
      )}
    </div>
  );
}
