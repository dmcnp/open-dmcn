import React from 'react';
import './UsageMeter.css';

/** Props for the quota / usage indicator. */
export interface UsageMeterProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'children'> {
  /** Current usage amount. */
  value: number;
  /** Maximum (full) amount. @default 100 */
  max?: number;
  /** Label shown above the track, e.g. "Storage". */
  label?: string;
  /** Track thickness. @default "md" */
  size?: 'sm' | 'md' | 'lg';
  /**
   * Fill color. "auto" derives it from the fill level
   * (brand → warning ≥75% → danger ≥90%). @default "auto"
   */
  variant?: 'auto' | 'brand' | 'success' | 'warning' | 'danger';
  /**
   * Override the right-side readout. Defaults to the rounded percent
   * (e.g. "67%"). Pass "8.2 GB of 15 GB" for absolute values, or "" to hide.
   */
  valueText?: string;
  /** Helper text below the track, e.g. "Resets on Jul 1". */
  caption?: string;
}

/**
 * Quota / usage indicator. Shows a labeled progress track with a value
 * readout, e.g. "You've used 67% of your quota". Auto-colors by fill
 * level (brand → warning ≥75% → danger ≥90%) unless `variant` is set.
 */
export function UsageMeter({
  value,
  max = 100,
  label = '',
  size = 'md',
  variant = 'auto',
  valueText,
  caption,
  className = '',
  ...rest
}: UsageMeterProps): React.ReactElement {
  const pct = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0;
  const resolved =
    variant !== 'auto' ? variant : pct >= 90 ? 'danger' : pct >= 75 ? 'warning' : 'brand';
  const readout = valueText != null ? valueText : `${Math.round(pct)}%`;
  const cls = ['dmcn-usage', `dmcn-usage--${size}`, `dmcn-usage--${resolved}`, className]
    .filter(Boolean)
    .join(' ');
  return (
    <div className={cls} {...rest}>
      {(label || valueText !== '') && (
        <div className="dmcn-usage__head">
          {label && <span className="dmcn-usage__label">{label}</span>}
          {readout !== '' && <span className="dmcn-usage__value">{readout}</span>}
        </div>
      )}
      <div
        className="dmcn-usage__track"
        role="progressbar"
        aria-valuenow={Math.round(pct)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label || 'Usage'}
      >
        <div className="dmcn-usage__fill" style={{ width: `${pct}%` }} />
      </div>
      {caption && <span className="dmcn-usage__caption">{caption}</span>}
    </div>
  );
}
