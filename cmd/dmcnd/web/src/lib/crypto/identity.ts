// Identity-record self-signing. The self-signature is computed over a
// domain-separation context PREFIX followed by the record's signable bytes —
// it must match Go's signCtx(ctxIdentitySelf, …) in
// internal/core/identity/identity.go, where
//   ctxIdentitySelf = "dmcn-identity-self-v1\x00"
// Signing the bare signable bytes (without this prefix) produces a signature the
// Go directory rejects with "identity record signature verification failed".
import { sign } from './sign';

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
