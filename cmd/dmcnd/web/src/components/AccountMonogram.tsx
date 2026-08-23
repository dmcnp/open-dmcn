// A monogram, not an avatar: an account is an address, and two initials from it are a
// stable, offline, unspoofable way to tell one apart at a glance. No image, no
// gravatar, nothing fetched.
//
// This is the ONE place a person is still drawn as a box of initials, and only for
// your own account in the header. Counterparties get a KindIcon instead: for someone
// else the useful fact is which network they are on, not a tinted circle that looks
// like identity but conveys nothing an impersonator could not also produce.

function initialsOf(address: string): string {
  const local = address.split('@')[0] || address;
  return local.slice(0, 2).toUpperCase();
}

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
