// Seal-format generations shared by the envelope encrypt and decrypt paths.
//
// Mirrors Go: internal/core/message/encrypt.go (KDFv1/KDFv2, cekWrapInfo) and
// internal/core/message/split.go (headerAAD/bodyAAD). Byte parity here is load-bearing — these
// values feed HKDF and AES-GCM, so any divergence from Go produces a different key or a failed
// tag rather than a visible error.
//
// Every wrap states its own generation on the wire (RecipientRecord.kdf; see
// proto/core/message.proto). Readers dispatch on that value and never attempt trial decryption:
// an implementation of this format needs to read one field, not try derivations in turn.

const enc = new TextEncoder();

// ABSENT (0) MEANS 1. A protocol rule, not a compatibility shim: every wrap written before the
// field existed used generation 1, and stored envelopes are never re-encrypted.
export const KDF_V1 = 1;
export const KDF_V2 = 2;

// PRODUCER_KDF is the generation new wraps are written with. Readers dispatch on what each
// record declares, so this only decides what we emit.
export const PRODUCER_KDF = KDF_V2;

export function normalizeKDF(v: number | undefined): number {
  return !v ? KDF_V1 : v;
}

const CEK_WRAP_INFO_V1 = enc.encode('dmcn-cek-wrap-v1');
const CEK_WRAP_LABEL_V2 = enc.encode('dmcn-cek-wrap-v2');

// cekWrapInfo returns the HKDF info for a generation, or throws for one this build does not
// know. Refusing an unknown generation is deliberate: a reader that cannot reproduce the
// derivation must say so rather than fall back and appear to fail authentication.
export function cekWrapInfo(kdf: number, ephPub: Uint8Array, rcptPub: Uint8Array): Uint8Array {
  switch (normalizeKDF(kdf)) {
    case KDF_V1:
      return CEK_WRAP_INFO_V1;
    case KDF_V2:
      return cekWrapInfoV2(ephPub, rcptPub);
    default:
      throw new Error(`unknown CEK-wrap derivation ${kdf}`);
  }
}

// cekWrapInfoV2 binds the key-wrapping key to the two keys it was derived for, mirroring
// RFC 9180 section 4.1 DHKEM's kem_context = concat(enc, pkRm). Both are fixed 32-byte keys,
// which is what makes the concatenation unambiguous.
export function cekWrapInfoV2(ephPub: Uint8Array, rcptPub: Uint8Array): Uint8Array {
  if (ephPub.length !== 32 || rcptPub.length !== 32) {
    throw new Error('cek wrap: ephemeral and recipient keys must be 32 bytes');
  }
  const info = new Uint8Array(CEK_WRAP_LABEL_V2.length + 64);
  info.set(CEK_WRAP_LABEL_V2, 0);
  info.set(ephPub, CEK_WRAP_LABEL_V2.length);
  info.set(rcptPub, CEK_WRAP_LABEL_V2.length + 32);
  return info;
}

// AEAD additional-data labels distinguishing the two blobs a split envelope seals under ONE CEK.
//
// Hygiene, not a vulnerability fix: header and body share a CEK and differ only by nonce, so
// without a label a relay can serve the header blob where the body belongs and it AEAD-opens,
// failing later on bodyHash. These move that rejection to the AEAD. They are NOT a defence
// against surreptitious forwarding — additional data is authenticated under the CEK, and that
// adversary holds the CEK. What catches that is checking the signed recipient address.
export const AAD_HEADER_V1 = enc.encode('dmcn-aad-hdr-v1\x00');
export const AAD_BODY_V1 = enc.encode('dmcn-aad-body-v1\x00');

// headerAAD and bodyAAD key off the SAME generation the recipient record carries, so an
// envelope's blobs and its wraps can never disagree. Generation 1 predates the labels.
export function headerAAD(kdf: number): Uint8Array | undefined {
  return normalizeKDF(kdf) === KDF_V1 ? undefined : AAD_HEADER_V1;
}

export function bodyAAD(kdf: number): Uint8Array | undefined {
  return normalizeKDF(kdf) === KDF_V1 ? undefined : AAD_BODY_V1;
}
