// Browser half of the cross-implementation known-answer vectors.
//
// The Go half is internal/core/message/kemvector_test.go and carries the same constants. Go and
// the browser are two independent implementations of one wire format, and until these existed
// the only automated parity check was golden PROTOBUF hex — which works because a protobuf
// encoding is structurally eyeballable, and stops working the moment a derivation context is a
// computed value rather than a constant. An HKDF output cannot be checked by eye.
//
// Change a label, a concatenation order, or the HKDF salt on either side and one suite goes red.
//
// Fixed inputs: ephemeral private = 32x0x01, recipient private = 32x0x02, CEK = 32x0x03,
// CEK nonce = 12x0x04, AEAD key = 32x0x05, AEAD nonce = 12x0x06.

import { describe, it, expect } from 'vitest';
import { importX25519PrivateKey, importX25519PublicKey } from './keys';
import { unwrapCEK, aesGcmDecrypt, unpadPayload } from './decrypt';
import { cekWrapInfo, cekWrapInfoV2, headerAAD, bodyAAD, AAD_HEADER_V1, AAD_BODY_V1, KDF_V1, KDF_V2 } from './sealVersion';
import { bufferSource } from './bytes';

const VEC = {
  ephPub: 'a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209',
  rcptPub: 'ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59',
  shared: '2ed76ab549b1e73c031eb49c9448f0798aea81b698279a0c3dc3e49fbfc4b953',
  kwkV1: 'd4289fa1219bc84591141148ac91cb35b2b70c9fe85f541a5d59ef88b42a23ae',
  kwkV2: '3014321754048b6b004d90a76824cd4a85b185d09c409de6953e35179b1fc033',
  wrappedV1: '2b925ba17c7250e6d9d1bcc4e9e5b9f4005eaab1ff0945cef7cb9dc015cd38fc',
  tagV1: '50baf3c9cfc15d33b07b3f85ec3e7852',
  wrappedV2: '3f79601eb4cb4b284265e5da2dbba17b422a0a4c88273aed23e05f7850859250',
  tagV2: '1e82bad41401e8c735b6f0cce60b7958',
  // Header and body ciphertexts are IDENTICAL: same key, nonce and plaintext. Only the tags
  // differ, which is exactly what the AEAD labels buy and why they separate the two blobs.
  aeadPlain: 'dmcn parity vector payload',
  hdrCT: 'fed6191f79f9837fca198a956849c3c0e7e2e7b28791e2c2a2b4',
  hdrTag: '5683e294a2dac2d4dd80de833320579b',
  bodyCT: 'fed6191f79f9837fca198a956849c3c0e7e2e7b28791e2c2a2b4',
  bodyTag: '10d874712fd9a3b9b4b9659158957be1',
};

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map(h => parseInt(h, 16)));
const fill = (b: number) => new Uint8Array(32).fill(b);

async function kwkFor(shared: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const sharedKey = await crypto.subtle.importKey('raw', bufferSource(shared), 'HKDF', false, ['deriveKey']);
  const kwk = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: bufferSource(info) },
    sharedKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );
  return new Uint8Array(await crypto.subtle.exportKey('raw', kwk));
}

function record(wrapped: string, tag: string, kdf?: number) {
  return {
    recipientXPub: unhex(VEC.rcptPub),
    ephemeralXPub: unhex(VEC.ephPub),
    wrappedCek: unhex(wrapped),
    cekNonce: new Uint8Array(12).fill(0x04),
    cekTag: unhex(tag),
    kdf,
  };
}

describe('KEM derivation vectors', () => {
  it('derives the pinned shared secret', async () => {
    // Mirrors what the browser actually does: our private half against their ephemeral public.
    const priv = await importX25519PrivateKey(fill(0x02));
    const ephPub = await importX25519PublicKey(unhex(VEC.ephPub));
    const bits = await crypto.subtle.deriveBits({ name: 'X25519', public: ephPub }, priv, 256);
    expect(hex(new Uint8Array(bits))).toBe(VEC.shared);
  });

  it('derives both key-wrapping keys', async () => {
    // The empty salt matches Go's nil — RFC 5869 section 2.2 makes both 32 zero bytes. If that
    // equivalence ever breaks, these two values move and Go's suite fails alongside this one.
    const shared = unhex(VEC.shared);
    expect(hex(await kwkFor(shared, cekWrapInfo(KDF_V1, unhex(VEC.ephPub), unhex(VEC.rcptPub))))).toBe(VEC.kwkV1);
    expect(hex(await kwkFor(shared, cekWrapInfoV2(unhex(VEC.ephPub), unhex(VEC.rcptPub))))).toBe(VEC.kwkV2);
  });

  it('rejects a context built from the wrong key width', () => {
    expect(() => cekWrapInfoV2(new Uint8Array(31), unhex(VEC.rcptPub))).toThrow();
  });
});

describe('unwrapCEK dispatches on the declared generation', () => {
  it.each([
    // kdf omitted is the pre-field encoding. ABSENT MUST MEAN 1 — that mapping is what lets
    // stored mail keep opening with no compatibility branch.
    ['absent kdf means generation 1', VEC.wrappedV1, VEC.tagV1, undefined],
    ['explicit generation 1', VEC.wrappedV1, VEC.tagV1, KDF_V1],
    ['generation 2 (context-bound)', VEC.wrappedV2, VEC.tagV2, KDF_V2],
  ])('opens %s', async (_name, wrapped, tag, kdf) => {
    const priv = await importX25519PrivateKey(fill(0x02));
    const cek = await unwrapCEK(record(wrapped, tag, kdf as number | undefined), priv, unhex(VEC.rcptPub));
    expect(hex(cek)).toBe(hex(fill(0x03)));
  });

  it('does not fall back across generations', async () => {
    // No trial decryption. A mislabelled wrap must fail rather than be discovered by attempting
    // the other derivation — that is the whole point of the field.
    const priv = await importX25519PrivateKey(fill(0x02));
    await expect(unwrapCEK(record(VEC.wrappedV2, VEC.tagV2, KDF_V1), priv, unhex(VEC.rcptPub))).rejects.toThrow();
    await expect(unwrapCEK(record(VEC.wrappedV1, VEC.tagV1, KDF_V2), priv, unhex(VEC.rcptPub))).rejects.toThrow();
  });

  it('refuses an unknown generation outright', async () => {
    const priv = await importX25519PrivateKey(fill(0x02));
    await expect(unwrapCEK(record(VEC.wrappedV2, VEC.tagV2, 99), priv, unhex(VEC.rcptPub)))
      .rejects.toThrow(/unknown CEK-wrap derivation/);
  });

  it('refuses a generation-2 record under the wrong recipient context', async () => {
    const priv = await importX25519PrivateKey(fill(0x02));
    // Same private key, claiming a different public half: generation 2 binds to it, so the wrap
    // must not open. Generation 1 cannot be caught this way because it binds nothing — which is
    // the entire reason the context exists.
    await expect(unwrapCEK(record(VEC.wrappedV2, VEC.tagV2, KDF_V2), priv, fill(0x09))).rejects.toThrow();
  });

  it('keys the blob labels off the same generation', () => {
    expect(headerAAD(KDF_V1)).toBeUndefined();
    expect(bodyAAD(KDF_V1)).toBeUndefined();
    expect(headerAAD(KDF_V2)).toBe(AAD_HEADER_V1);
    expect(bodyAAD(KDF_V2)).toBe(AAD_BODY_V1);
  });
});

describe('AEAD label vectors', () => {
  const key = fill(0x05);
  const nonce = new Uint8Array(12).fill(0x06);

  it('has identical ciphertext but different tags', () => {
    expect(VEC.hdrCT).toBe(VEC.bodyCT);
    expect(VEC.hdrTag).not.toBe(VEC.bodyTag);
  });

  it.each([
    ['header', VEC.hdrCT, VEC.hdrTag, AAD_HEADER_V1],
    ['body', VEC.bodyCT, VEC.bodyTag, AAD_BODY_V1],
  ])('opens the %s blob under its own label', async (_n, ct, tag, label) => {
    const pt = await aesGcmDecrypt(key, nonce, unhex(ct), unhex(tag), label as Uint8Array);
    expect(new TextDecoder().decode(pt)).toBe(VEC.aeadPlain);
  });

  it('refuses the header blob under the body label, and under none', async () => {
    // The swap these labels exist to stop. Before them it opened cleanly and was caught one
    // layer later, on bodyHash.
    await expect(aesGcmDecrypt(key, nonce, unhex(VEC.hdrCT), unhex(VEC.hdrTag), AAD_BODY_V1)).rejects.toThrow();
    await expect(aesGcmDecrypt(key, nonce, unhex(VEC.hdrCT), unhex(VEC.hdrTag))).rejects.toThrow();
  });
});

describe('unpadPayload', () => {
  it('round-trips', () => {
    const padded = new Uint8Array(16);
    padded.set([0, 0, 0, 2, 0xaa, 0xbb]);
    expect(hex(unpadPayload(padded))).toBe('aabb');
  });

  it('rejects a length prefix with the high bit set', () => {
    // The Go/browser divergence this fixed: `<<` is SIGNED in JS, so 0x80000000 went negative,
    // slipped past the bounds check and returned an EMPTY array, where Go returned the whole
    // padded buffer. Two implementations, two different wrong answers. Both now throw.
    expect(() => unpadPayload(new Uint8Array([0x80, 0, 0, 0, 0, 0, 0, 0]))).toThrow();
  });

  it('rejects a short buffer and an over-long prefix', () => {
    expect(() => unpadPayload(new Uint8Array([0, 0]))).toThrow();
    expect(() => unpadPayload(new Uint8Array([0, 0, 0, 255, 0]))).toThrow();
  });
});

// --- envelope wire parity ---------------------------------------------------
//
// The STORE signature is over SHA-256 of the marshaled EncryptedEnvelope, and the relay
// recomputes that hash from its own re-marshal — so one byte of disagreement between Go's
// encoder and this one makes every send fail verification at the relay. Adding
// RecipientRecord.kdf changed these bytes.
//
// The constant below is asserted from BOTH sides: here, and by
// TestKDFv2EnvelopeWireParityWithBrowser in internal/core/message/v1parity_test.go. Regenerate
// both together or not at all. Nothing else in the tree cross-checks the envelope encoder.

import { encodeSplitEnvelope } from './protobuf';

const KDFV2_ENVELOPE_HEX =
  '080212100102030405060708090a0b0c0d0e0f101a9a010a106465666768696a6b6c6d6e6f707172' +
  '7312200a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728291a20323334' +
  '35363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f50512220c8c9cacbcccdcecfd0' +
  'd1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e72a0c464748494a4b4c4d4e4f5051321050' +
  '5152535455565758595a5b5c5d5e5f38022a0c0000000000000000000000003210000000000000' +
  '0000000000000000000040cea4c1b0064a2000000000000000000000000000000000000000000000' +
  '00000000000000000000521805060708090a0b0c0d0e0f101112131415161718191a1b1c5a0c1516' +
  '1718191a1b1c1d1e1f2062101f202122232425262728292a2b2c2d2e6880087228090a0b0c0d0e0f' +
  '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f307a0c292a2b2c2d' +
  '2e2f3031323334820110333435363738393a3b3c3d3e3f404142880180209201243c3d3e3f404142' +
  '434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f';

// fill mirrors the Go fixture's `fill(n, base)`: byte i == (base+i) mod 256.
const fillPattern = (n: number, base: number) =>
  new Uint8Array(Array.from({ length: n }, (_, i) => (base + i) % 256));

describe('envelope wire parity with Go', () => {
  it('encodes a kdf=2 split envelope byte-identically', async () => {
    const bytes = await encodeSplitEnvelope({
      version: 2,
      messageId: fillPattern(16, 1),
      createdAt: 1712345678,
      recipients: [{
        deviceId: fillPattern(16, 100),
        recipientXPub: fillPattern(32, 10),
        ephemeralXPub: fillPattern(32, 50),
        wrappedCek: fillPattern(32, 200),
        cekNonce: fillPattern(12, 70),
        cekTag: fillPattern(16, 80),
        kdf: KDF_V2,
      }],
      encryptedHeader: fillPattern(24, 5),
      headerNonce: fillPattern(12, 21),
      headerTag: fillPattern(16, 31),
      headerSizeClass: 1024,
      encryptedBody: fillPattern(40, 9),
      bodyNonce: fillPattern(12, 41),
      bodyTag: fillPattern(16, 51),
      bodySizeClass: 4096,
      bodyContentAddress: fillPattern(36, 60),
    });
    expect(hex(bytes)).toBe(KDFV2_ENVELOPE_HEX);
  });
});
