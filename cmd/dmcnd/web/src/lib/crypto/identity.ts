// Identity-record self-signing. The self-signature is computed over a
// domain-separation context PREFIX followed by the record's signable bytes —
// it must match Go's signCtx(ctxIdentitySelf, …) in
// internal/core/identity/identity.go, where
//   ctxIdentitySelf = "dmcn-identity-self-v1\x00"
// Signing the bare signable bytes (without this prefix) produces a signature the
// Go directory rejects with "identity record signature verification failed".
import { sign, verify } from './sign';

/** "dmcn-identity-self-v1" + a trailing NUL, as raw bytes. */
export const ID_SELF_CTX: Uint8Array = (() => {
  const tag = new TextEncoder().encode('dmcn-identity-self-v1');
  const out = new Uint8Array(tag.length + 1); // trailing NUL
  out.set(tag, 0);
  return out;
})();

/**
 * Produce an identity record's self-signature: Ed25519 over
 * ID_SELF_CTX || signableBytes, signed with the 32-byte Ed25519 seed.
 */
export async function signSelfSignature(seed: Uint8Array, signableBytes: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(ID_SELF_CTX.length + signableBytes.length);
  buf.set(ID_SELF_CTX, 0);
  buf.set(signableBytes, ID_SELF_CTX.length);
  return sign(seed, buf);
}

/**
 * Check an identity record's self-signature over ID_SELF_CTX || signableBytes.
 *
 * The counterpart to signSelfSignature, and it inherits that function's one sharp edge: the
 * signable bytes are RE-MARSHALED from the parsed record, so a record carrying a signed field
 * this bundle does not know about will not reproduce them and will not verify. That is the
 * documented cost of the schema rule (CLAUDE.md, "Adding a signed core field") and it fails in
 * the safe direction here — a record we cannot verify explains nothing, which is stricter than
 * what it would have said.
 */
export async function verifySelfSignature(
  ed25519Pub: Uint8Array,
  signableBytes: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if ((ed25519Pub?.length ?? 0) !== 32 || (signature?.length ?? 0) !== 64) return false;
  const buf = new Uint8Array(ID_SELF_CTX.length + signableBytes.length);
  buf.set(ID_SELF_CTX, 0);
  buf.set(signableBytes, ID_SELF_CTX.length);
  return verify(ed25519Pub, buf, signature);
}

/**
 * "dmcn-address-removal-v1" + a trailing NUL, as raw bytes. Must match Go's
 * ctxAddressRemoval in internal/core/identity/identity.go.
 */
export const ADDRESS_REMOVAL_CTX: Uint8Array = (() => {
  const tag = new TextEncoder().encode('dmcn-address-removal-v1');
  const out = new Uint8Array(tag.length + 1); // trailing NUL
  out.set(tag, 0);
  return out;
})();

/**
 * Prefix a removal record's signable bytes with its domain-separation context, ready to sign.
 *
 * The signature may come from the domain root OR from the key the address is bound to — an
 * address may always retire ITSELF. The two authorize different things: either suppresses the
 * binding, but only a root-signed record may free the address to be re-bound to a different key.
 * Callers here only ever produce the owner-signed kind. See open-dmcn SPEC.md section 1.
 */
export function removalSigningBytes(signableBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(ADDRESS_REMOVAL_CTX.length + signableBytes.length);
  buf.set(ADDRESS_REMOVAL_CTX, 0);
  buf.set(signableBytes, ADDRESS_REMOVAL_CTX.length);
  return buf;
}

/**
 * "dmcn-identity-rotation-v1" + a trailing NUL. Must match Go's ctxIdentityRotation.
 *
 * This context covers the outgoing key's CONSENT to hand an address over.
 */
export const ROTATION_CTX: Uint8Array = (() => {
  const tag = new TextEncoder().encode('dmcn-identity-rotation-v1');
  const out = new Uint8Array(tag.length + 1); // trailing NUL
  out.set(tag, 0);
  return out;
})();

/**
 * "dmcn-identity-rotation-accept-v1" + a trailing NUL. Must match Go's
 * ctxIdentityRotationAccept.
 *
 * Deliberately a DIFFERENT context from ROTATION_CTX: an acceptance by the incoming key must
 * never verify as a consent by the outgoing one, or a key that merely received an address could
 * be made to look as though it had handed the address on.
 */
export const ROTATION_ACCEPT_CTX: Uint8Array = (() => {
  const tag = new TextEncoder().encode('dmcn-identity-rotation-accept-v1');
  const out = new Uint8Array(tag.length + 1); // trailing NUL
  out.set(tag, 0);
  return out;
})();

/** Prefix a rotation entry's consent bytes with their context, ready to sign or verify. */
export function rotationConsentSigningBytes(consentBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(ROTATION_CTX.length + consentBytes.length);
  buf.set(ROTATION_CTX, 0);
  buf.set(consentBytes, ROTATION_CTX.length);
  return buf;
}

/** Prefix a rotation entry's acceptance bytes with their context, ready to sign or verify. */
export function rotationAcceptSigningBytes(acceptBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(ROTATION_ACCEPT_CTX.length + acceptBytes.length);
  buf.set(ROTATION_ACCEPT_CTX, 0);
  buf.set(acceptBytes, ROTATION_ACCEPT_CTX.length);
  return buf;
}

/**
 * "dmcn-identity-rotation-device-v1" + a trailing NUL. Must match Go's
 * ctxIdentityRotationDevice.
 *
 * Separate from both account-key contexts so no one of the three attestations on a transition
 * can stand in for another.
 */
export const ROTATION_DEVICE_CTX: Uint8Array = (() => {
  const tag = new TextEncoder().encode('dmcn-identity-rotation-device-v1');
  const out = new Uint8Array(tag.length + 1); // trailing NUL
  out.set(tag, 0);
  return out;
})();

/** Prefix a rotation entry's device bytes with their context, ready to sign or verify. */
export function rotationDeviceSigningBytes(deviceBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(ROTATION_DEVICE_CTX.length + deviceBytes.length);
  buf.set(ROTATION_DEVICE_CTX, 0);
  buf.set(deviceBytes, ROTATION_DEVICE_CTX.length);
  return buf;
}
