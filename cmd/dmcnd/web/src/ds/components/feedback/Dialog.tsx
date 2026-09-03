import React from 'react';
import './Dialog.css';

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
