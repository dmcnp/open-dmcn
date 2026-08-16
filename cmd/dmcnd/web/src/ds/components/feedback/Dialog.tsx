import React from 'react';

let _dialogStyles = false;
function ensureDialogStyles(): void {
  if (_dialogStyles || typeof document === 'undefined') return;
  _dialogStyles = true;
  const s = document.createElement('style');
  s.setAttribute('data-dmcn', 'dialog');
  s.textContent = `
.dmcn-dialog__overlay{
  position:fixed;inset:0;z-index:100;background:rgba(12,16,16,0.45);
  display:flex;align-items:center;justify-content:center;padding:var(--space-4);
  animation:dmcnFade var(--dur-normal) var(--ease-standard);
}
[data-theme="dark"] .dmcn-dialog__overlay{background:rgba(0,0,0,0.6);}
.dmcn-dialog{
  position:relative;width:100%;max-width:440px;background:var(--surface-card);
  border:1px solid var(--border-default);border-radius:var(--radius-lg);box-shadow:var(--shadow-lg);
  font-family:var(--font-sans);animation:dmcnRise var(--dur-normal) var(--ease-out);
  /* Never taller than the viewport (dvh accounts for mobile browser chrome), and lay the
     head/body/footer out as a column so the body scrolls while the head+footer stay pinned —
     otherwise a tall form clips off-screen on short/landscape phones. */
  max-height:calc(100vh - var(--space-4) - var(--space-4));
  max-height:calc(100dvh - var(--space-4) - var(--space-4));
  display:flex;flex-direction:column;overflow:hidden;
}
.dmcn-dialog__head{flex:none;display:flex;align-items:flex-start;justify-content:space-between;gap:var(--space-4);padding:var(--space-5) var(--space-5) var(--space-3);}
.dmcn-dialog__title{font-size:var(--text-lg);font-weight:var(--weight-semibold);color:var(--text-strong);margin:0;}
.dmcn-dialog__close{appearance:none;border:none;background:transparent;color:var(--text-muted);cursor:pointer;display:flex;padding:2px;border-radius:var(--radius-sm);}
.dmcn-dialog__close:hover{background:var(--surface-hover);color:var(--text-strong);}
.dmcn-dialog__close svg{width:18px;height:18px;stroke-width:2;}
.dmcn-dialog__body{flex:1 1 auto;min-height:0;overflow-y:auto;padding:0 var(--space-5) var(--space-4);font-size:var(--text-md);color:var(--text-body);line-height:var(--leading-normal);}
.dmcn-dialog__footer{flex:none;display:flex;justify-content:flex-end;gap:var(--space-2);padding:var(--space-4) var(--space-5) var(--space-5);}
@keyframes dmcnFade{from{opacity:0}to{opacity:1}}
@keyframes dmcnRise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
`;
  document.head.appendChild(s);
}

const X = (): React.ReactElement => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeLinecap="square">
    <path d="M5 5l14 14M19 5L5 19" />
  </svg>
);

/** Props for the modal dialog. */
export interface DialogProps {
  /** Visibility (controlled). */
  open: boolean;
  /** Fires on overlay click, × button, or Escape. */
  onClose?: () => void;
  /** Header title. */
  title?: React.ReactNode;
  /** Footer slot — typically action Buttons. */
  footer?: React.ReactNode;
  /** Override the default 440px max width (e.g. a wider payment/checkout modal). */
  maxWidth?: number | string;
  children?: React.ReactNode;
}

/**
 * Modal dialog with overlay, optional title and footer slot.
 * Controlled via `open`; `onClose` fires on overlay click / × / Escape.
 */
export function Dialog({
  open,
  onClose,
  title,
  footer = null,
  maxWidth,
  children,
}: DialogProps): React.ReactElement | null {
  ensureDialogStyles();
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape' && onClose) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div
      className="dmcn-dialog__overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && onClose) onClose();
      }}
    >
      <div
        className="dmcn-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : undefined}
        style={maxWidth != null ? { maxWidth } : undefined}
      >
        <div className="dmcn-dialog__head">
          {title && <h2 className="dmcn-dialog__title">{title}</h2>}
          {onClose && (
            <button type="button" className="dmcn-dialog__close" aria-label="Close" onClick={onClose}>
              <X />
            </button>
          )}
        </div>
        <div className="dmcn-dialog__body">{children}</div>
        {footer && <div className="dmcn-dialog__footer">{footer}</div>}
      </div>
    </div>
  );
}
