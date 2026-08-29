import { initialsOf } from '../lib/accounts';

// A monogram, not an avatar: an account is an address, and two initials from it are a
// stable, offline, unspoofable way to tell one apart at a glance. No image, no
// gravatar, nothing fetched.
export function AccountMonogram({ address, size = 32 }: { address: string; size?: number }) {
  return (
    <div aria-hidden="true" style={{
      flex: 'none', width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'var(--brand-subtle)', color: 'var(--brand-text)', fontSize: Math.round(size * 0.375),
      fontWeight: 600, fontFamily: 'var(--font-mono)', borderRadius: 'var(--radius-sm)',
    }}>
      {initialsOf(address)}
    </div>
  );
}
