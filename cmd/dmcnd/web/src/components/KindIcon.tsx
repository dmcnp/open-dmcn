import { Icon } from './Icon';
import type { SenderKind } from '../lib/trust/senderKind';

/**
 * The one-glyph "which network is this person on" cue, shared by the mail list and
 * the contacts page so both speak the same language: a teal shield for a DMCN
 * identity, a muted envelope for a legacy email address reached over a bridge.
 * An unresolved kind renders an equally-sized blank, so nothing shifts when the
 * directory answer arrives.
 *
 * `trusted` upgrades the DMCN shield from teal to the blue trusted-contact colour —
 * the same blue, and the same "Trusted contact" wording, that the compose recipient
 * chips and the reader's trust badge use (trustView.ts), so one counterparty wears one
 * colour and one name everywhere they appear. It is deliberately an upgrade
 * of the DMCN shield and not its own glyph: the shape still says "end-to-end
 * encrypted", the colour adds "and you have verified who this is". A legacy contact
 * keeps the muted envelope no matter how trusted they are, because that glyph is a
 * statement about encryption and bridged mail has none to claim.
 */
export function KindIcon({ kind, trusted = false, size = 14 }: { kind: SenderKind; trusted?: boolean; size?: number }) {
  if (kind === 'dmcn') {
    return (
      <Icon
        name="shield-check"
        size={size}
        style={{ color: trusted ? 'var(--trust-contact)' : 'var(--trust-dmcn)', flex: 'none' }}
        title={trusted
          ? 'Trusted contact — end-to-end encrypted between your keys'
          : 'DMCN identity — this message is end-to-end encrypted between your keys'}
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
