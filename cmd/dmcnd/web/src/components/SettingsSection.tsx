// The two pieces every Account-tab section is built from: an uppercase eyebrow and the bordered
// surface its contents sit on.
//
// They live here rather than inside Settings because a section is not always the page's to frame.
// A section that exists only when a remote service offers the feature — bringing your own domain —
// has to decide for itself whether to appear at all, and a page that rendered the heading and card
// around it would leave an empty box whenever the answer was no.

import type { ReactNode } from 'react';

/** Uppercase section eyebrow, with optional right-aligned meta (a renewal date, a status). */
export function SectionHeading({ title, meta }: { title: string; meta?: ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 'var(--space-4)' }}>
      <h2 style={{ margin: 0, fontSize: 'var(--text-sm)', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{title}</h2>
      {meta && <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-subtle)' }}>{meta}</span>}
    </div>
  );
}

/** The bordered surface a section's contents sit on. One definition, so every card is the same
 *  card rather than several near-misses that drift apart. */
export function SettingsCard({ children }: { children: ReactNode }) {
  return (
    <div style={{
      background: 'var(--surface-card)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)',
      padding: 'var(--space-6)', display: 'flex', flexDirection: 'column', gap: 'var(--space-5)',
    }}>{children}</div>
  );
}

/** A whole section: eyebrow, then card. */
export function SettingsSection({ title, meta, children }: { title: string; meta?: ReactNode; children: ReactNode }) {
  return (
    <section style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      <SectionHeading title={title} meta={meta} />
      <SettingsCard>{children}</SettingsCard>
    </section>
  );
}
