import { describe, it, expect } from 'vitest';
import type { SenderTrust, SenderTrustKind } from '../crypto/senderTrust';
import { blockKey } from './category';

// Block must never put the bridge's key on the blocklist: every bridged message is signed by it,
// so one Block on a stranger's email would hide all regular email from then on. These pin which
// verdicts let Block pin the signing key and which fall back to the address.

const key = 'ab'.repeat(32);
const trust = (kind: SenderTrustKind): SenderTrust => ({ kind });

describe('blockKey', () => {
  it.each<SenderTrustKind>(['allowlisted', 'domain_verified', 'unknown_pending', 'record_changed', 'key_changed'])(
    'blocks the key when the directory confirms it (%s)',
    (kind: SenderTrustKind) => expect(blockKey(trust(kind), key)).toBe(key),
  );

  it.each<SenderTrustKind>(['directory_missing', 'key_mismatch', 'identity_unverifiable'])(
    'blocks the address only when the directory does not confirm the key (%s)',
    (kind: SenderTrustKind) => expect(blockKey(trust(kind), key)).toBeUndefined(),
  );

  it('blocks the address only before a verdict arrives', () => {
    expect(blockKey(null, key)).toBeUndefined();
  });

  it('has no key to block on a message without one', () => {
    expect(blockKey(trust('unknown_pending'), '')).toBeUndefined();
  });
});
