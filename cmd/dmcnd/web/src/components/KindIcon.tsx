import { Icon } from './Icon';
import type { SenderKind } from '../lib/trust/senderKind';

/**
 * The one-glyph "which network is this person on" cue, shared by the mail list and
 * the contacts page so both speak the same language: a teal shield for a DMCN
 * identity, a muted envelope for a legacy email address reached over a bridge.
 * An unresolved kind renders an equally-sized blank, so nothing shifts when the
 * directory answer arrives.
 */
export function KindIcon({ kind, size = 14 }: { kind: SenderKind; size?: number }) {
  if (kind === 'dmcn') {
    return (
      <Icon
        name="shield-check"
        size={size}
        style={{ color: 'var(--trust-dmcn)', flex: 'none' }}
        title="DMCN identity — this message is end-to-end encrypted between your keys"
      />
    );
  }
  if (kind === 'legacy') {
    return (
      <Icon
        name="mail"
        size={size}
        style={{ color: 'var(--text-muted)', flex: 'none' }}
        title="Legacy email — carried over a bridge, so it is not end-to-end encrypted"
      />
    );
  }
  return <span style={{ flex: 'none', width: size, height: size, display: 'inline-block' }} />;
}
