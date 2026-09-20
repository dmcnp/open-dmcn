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
import {
  encodeIdentitySignableBytes, encodeRemovalSignableBytes,
  encodeRotationDeviceBytes, encodeRotationConsentBytes, encodeRotationAcceptBytes,
  encodeIdentityRecord, decodeIdentityRecord,
} from './protobuf';
import { bodyContentAddress, snippetOf } from './split';

const VEC = {
  identityFull: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa063080a4a7da064002b80101d00103',
  identityMinimal: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa06',
  bodyCID: '015512203946fa8f9480c933c7f5efb0a06254d612940e924ecdebd2e041e2425802d306',
  removalSignable: '0801120e7061726974792e6578616d706c651a15766563746f72407061726974792e6578616d706c6522280a2007070707070707070707070707070707070707070707070707070707070707071080e2cfaa0628033081e2cfaa06',
  rotationDevice: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082a200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c32200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3880e2cfaa0640044a200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b52200707070707070707070707070707070707070707070707070707070707070707',
  rotationConsent: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082a200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c32200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3880e2cfaa0640044a200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b52200707070707070707070707070707070707070707070707070707070707070707624012121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212',
  rotationAccept: '08011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082a200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c32200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3880e2cfaa0640044a200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b522007070707070707070707070707070707070707070707070707070707070707076240121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212126a400e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e',
  identityWithChain: '08011215766563746f72407061726974792e6578616d706c651a200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c22200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d2880e2cfaa06d00104ea01b30308011215766563746f72407061726974792e6578616d706c651a200707070707070707070707070707070707070707070707070707070707070707222008080808080808080808080808080808080808080808080808080808080808082a200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c32200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3880e2cfaa0640044a200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b522007070707070707070707070707070707070707070707070707070707070707076240121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212121212126a400e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e72400f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0ff201201111111111111111111111111111111111111111111111111111111111111111',
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

// An address retiring ITSELF signs these bytes. Go's half is
// internal/core/identity/selfretire_vector_test.go. If the two encoders drift, the fleet rejects
// every self-retirement with nothing more useful than "signature invalid" — so pin the bytes.
describe('address removal signable bytes (Go AddressRemovalRecord.signableBytes)', () => {
  it('matches the Go vector, with the signature excluded', async () => {
    const b = await encodeRemovalSignableBytes({
      version: 1,
      domain: 'parity.example',
      address: 'vector@parity.example',
      removedBindings: [{ ed25519PublicKey: fill(32, 0x07), removedAt: 1_700_000_000 }],
      revision: 3,
      createdAt: 1_700_000_001,
    });
    expect(hex(b)).toBe(VEC.removalSignable);
  });
});

// The rotation half. A transition carries TWO signatures over DIFFERENT extents — consent by the
// outgoing key over fields 1-11, acceptance by the incoming key over 1-12, so the acceptance
// covers the consent. Encoding either extent differently from Go produces entries the other side
// rejects as forged, and nothing about that would be visible short of a rotation failing in
// production. The Go half is TestParityVectorRotationEntry.
//
// Fixed inputs: retired Ed25519 = 32x0x07, retired X25519 = 32x0x08, next Ed25519 = 32x0x0c,
// next X25519 = 32x0x0d, rotated 1700000000, next revision 4, prev signature hash = 32x0x0b,
// device signature = 64x0x12, consent signature = 64x0x0e, acceptance signature = 64x0x0f,
// recovery key = 32x0x11.
describe('rotation entry signing bytes (Go identity.RotationEntry)', () => {
  const entry = {
    version: 1, address: 'vector@parity.example',
    retiredEd25519PublicKey: fill(32, 0x07), retiredX25519PublicKey: fill(32, 0x08),
    nextEd25519PublicKey: fill(32, 0x0c), nextX25519PublicKey: fill(32, 0x0d),
    rotatedAt: 1_700_000_000, nextRevision: 4,
    prevSignatureHash: fill(32, 0x0b),
    authorizingEd25519PublicKey: fill(32, 0x07),
  };

  it('device bytes: the transition alone, before any signature covers it', async () => {
    expect(hex(await encodeRotationDeviceBytes(entry))).toBe(VEC.rotationDevice);
  });

  it('consent bytes: the device attestation is covered, the account signatures are not', async () => {
    const b = await encodeRotationConsentBytes({ ...entry, deviceSignature: fill(64, 0x12) });
    expect(hex(b)).toBe(VEC.rotationConsent);
    // Consent must extend the device bytes, so an outgoing key cannot consent to a handover
    // and have a different device attestation swapped in afterwards.
    expect(hex(b).startsWith(VEC.rotationDevice)).toBe(true);
  });

  it('accept bytes: the consent signature is covered, its own is not', async () => {
    const b = await encodeRotationAcceptBytes({ ...entry, deviceSignature: fill(64, 0x12), signature: fill(64, 0x0e), nextSignature: fill(64, 0x0f) });
    expect(hex(b)).toBe(VEC.rotationAccept);
    // The acceptance must extend the consent, never replace it.
    expect(hex(b).startsWith(VEC.rotationConsent)).toBe(true);
  });

  it('a record carrying a chain: entries nest with both signatures, and the recovery key is signed', async () => {
    const b = await encodeIdentitySignableBytes({
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x0c), x25519PublicKey: fill(32, 0x0d),
      createdAt: 1_700_000_000, expiresAt: 0,
      relayHints: [], verificationTier: 0, revision: 4,
      rotationChain: [{ ...entry, deviceSignature: fill(64, 0x12), signature: fill(64, 0x0e), nextSignature: fill(64, 0x0f) }],
      recoveryEd25519PublicKey: fill(32, 0x11),
    });
    expect(hex(b)).toBe(VEC.identityWithChain);
  });

  it('excludes everything the OWNER does not sign, including what a served record carries', async () => {
    // Go's signableBytes() builds a fresh message from the owner-signed fields alone, so every
    // operator-owned part of a record is outside the signature: relay_hints, the address and
    // routing credentials, the attestations, and the signature itself. A record decoded off the
    // wire carries them; one built in this file does not — which is why only a real record ever
    // caught a version of this encoder that let them through, and why the case is pinned here.
    const base = {
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x07), x25519PublicKey: fill(32, 0x08),
      createdAt: 1_700_000_000, expiresAt: 0, relayHints: [], verificationTier: 0,
    };
    const dressed = await encodeIdentitySignableBytes({
      ...base,
      relayHints: ['/dns4/relay.parity.example/tcp/7400/p2p/12D3KooWNnU1S2BMncbGpPPqWhPZQQKNtNmH5YnCaHuvti6xzVbL'],
      selfSignature: fill(64, 0x0b),
      routingCredential: { version: 1, subject: fill(32, 0x07) },
      addressCredential: { version: 1, subject: fill(32, 0x07) },
      attestations: [{ version: 1 }],
      operatorCredentials: [{ version: 1 }],
    } as never);
    expect(hex(dressed)).toBe(VEC.identityMinimal);
  });

  it('survives a decode, which is where an absent field stops being absent', async () => {
    // protobufjs answers for fields the sender never encoded, from the message PROTOTYPE: a
    // decoded record hands back expires_at as a zero Long rather than undefined, and a zero Long
    // is an object, so the canonicaliser does not recognise it as a default. An encoder that read
    // its inputs unconditionally would therefore emit a field that was not on the wire, and no
    // signature would ever cover the result.
    const record = await encodeIdentityRecord({
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x07), x25519PublicKey: fill(32, 0x08),
      createdAt: 1_700_000_000, expiresAt: 0, relayHints: [], verificationTier: 0,
    });
    expect(hex(await encodeIdentitySignableBytes(await decodeIdentityRecord(record)))).toBe(VEC.identityMinimal);
  });

  it('a record that never rotated encodes exactly as it did before the fields existed', async () => {
    // The precondition for adding a signed core field at all: an empty chain and an absent
    // recovery key must contribute no bytes, or every bundle predating the schema starts
    // rejecting every record on the network.
    const base = {
      version: 1, address: 'vector@parity.example',
      ed25519PublicKey: fill(32, 0x07), x25519PublicKey: fill(32, 0x08),
      createdAt: 1_700_000_000, expiresAt: 0, relayHints: [], verificationTier: 0,
    };
    expect(hex(await encodeIdentitySignableBytes({ ...base, rotationChain: [], recoveryEd25519PublicKey: new Uint8Array(0) })))
      .toBe(VEC.identityMinimal);
  });
});
