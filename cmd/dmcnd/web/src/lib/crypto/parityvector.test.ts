// Browser half of the identity/body known-answer vectors. The Go halves are
// internal/core/identity/parityvector_test.go and internal/core/message/parityvector_test.go in
// the product repository, with the same constants.
//
// Three things the browser encodes on its own and Go verifies byte-for-byte: the identity
// record's self-signed bytes (which fields the signature excludes, how proto3 defaults vanish,
// the field numbers of require_onion and revision), the body's content address, and the
// header snippet. Change either side and one suite goes red.
//
// Fixed inputs: Ed25519 public = 32x0x07, X25519 public = 32x0x08, created 1700000000,
// expires 1800000000 (full record only); body nonce 12x0x04, ciphertext 26x0x09, tag 16x0x0a.

import { describe, it, expect } from 'vitest';
import { encodeIdentitySignableBytes } from './protobuf';
import { bodyContentAddress, snippetOf } from './split';

const VEC = {
  identityFull: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa063080a4a7da064002b80101d00103',
  identityMinimal: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa06',
  bodyCID: '015512203946fa8f9480c933c7f5efb0a06254d612940e924ecdebd2e041e2425802d306',
};

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const utf8 = (s: string) => new TextEncoder().encode(s);

describe('identity record signable bytes (Go identity.signableBytes)', () => {
  it('full record: every self-signed field, relay hints and the signature excluded', async () => {
    const b = await encodeIdentitySignableBytes({
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x07), x25519PublicKey: fill(32, 0x08),
      createdAt: 1_700_000_000, expiresAt: 1_800_000_000,
      relayHints: ['/dns4/relay.parity.example/tcp/7400/p2p/12D3KooWNnU1S2BMncbGpPPqWhPZQQKNtNmH5YnCaHuvti6xzVbL'],
      verificationTier: 2, requireOnion: true, revision: 3,
    });
    expect(hex(b)).toBe(VEC.identityFull);
  });

  it('minimal record: proto3 defaults are absent from the bytes, as in Go', async () => {
    const b = await encodeIdentitySignableBytes({
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x07), x25519PublicKey: fill(32, 0x08),
      createdAt: 1_700_000_000, expiresAt: 0,
      relayHints: [], verificationTier: 0,
    });
    expect(hex(b)).toBe(VEC.identityMinimal);
  });
});

describe('body content address (Go message.ComputeBodyContentAddress)', () => {
  it('is CIDv1 raw sha2-256 over nonce||ciphertext||tag', async () => {
    expect(hex(await bodyContentAddress(fill(12, 0x04), fill(26, 0x09), fill(16, 0x0a)))).toBe(VEC.bodyCID);
  });
});

describe('snippet (Go message.snippetOf)', () => {
  it('matches the Go cases byte for byte', () => {
    expect(snippetOf('text/plain', utf8('hello, parity'))).toBe('hello, parity');
    // A rune straddling byte 140 is dropped whole.
    expect(snippetOf('text/plain', utf8('a'.repeat(138) + '€uro'))).toBe('a'.repeat(138));
    // Exactly 140 ASCII bytes are kept whole; the tail is cut.
    expect(snippetOf('text/plain', utf8('b'.repeat(140) + 'tail'))).toBe('b'.repeat(140));
    // A non-text body has no snippet.
    expect(snippetOf('text/html', utf8('<b>x</b>'))).toBe('');
    // Multibyte text under the cap is intact.
    expect(snippetOf('text/plain', utf8('héllo wörld ✓'))).toBe('héllo wörld ✓');
  });
});
