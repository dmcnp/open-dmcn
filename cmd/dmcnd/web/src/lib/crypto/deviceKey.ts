// The DEVICE key: this browser's own signing key on one mailbox.
//
// It answers a different question from the account key, and the whole device registry rests on
// the two staying separate. The account key says whose mailbox this is; the device key says the
// request comes from somewhere the owner approved. A relay that has enrolled devices demands
// both, so an account key copied out of a backup export opens nothing on its own.
//
// That property only holds if a device key genuinely cannot travel, which is why it is generated
// NON-EXTRACTABLE. The platform refuses to hand the private bytes back to anyone, including this
// code — so it cannot end up in the encrypted keystore, the backup file or the pairing clone
// payload by oversight. The exclusion is enforced, not merely intended.
//
// Keyed PER ACCOUNT rather than per browser. One key shared across accounts would present the
// same public key to a relay for each of them, quietly linking identities a user keeps apart; a
// second account on the same browser enrols separately, as it should.
import { DEVICE_STORE, idbDelete, idbGet, idbPut } from './idb';
import { bufferSource } from './bytes';

/** This browser's signing key for one mailbox. The private half never leaves the platform. */
export interface DeviceKey {
  /** Raw 32-byte Ed25519 public key — the device's identity on the mailbox. */
  publicKey: Uint8Array;
  /** Sign with the non-extractable handle. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

interface StoredDeviceKey {
  publicKey: Uint8Array;
  privateKey: CryptoKey;
}

const deviceKeyRef = (address: string) => `device-key:${address.toLowerCase()}`;

function wrap(stored: StoredDeviceKey): DeviceKey {
  return {
    publicKey: stored.publicKey,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      const sig = await crypto.subtle.sign('Ed25519', stored.privateKey, bufferSource(data));
      return new Uint8Array(sig);
    },
  };
}

/**
 * Load this browser's device key for `address`, or null if it has never made one.
 *
 * Null is the ordinary answer on a device that has not enrolled yet, and callers treat it as
 * "not enrolled here" rather than an error.
 */
export async function loadDeviceKey(address: string): Promise<DeviceKey | null> {
  try {
    const stored = await idbGet<StoredDeviceKey>(DEVICE_STORE, deviceKeyRef(address));
    if (!stored?.privateKey || !stored.publicKey?.length) return null;
    return wrap(stored);
  } catch {
    // A browser that cannot revive a stored handle (private windows, cleared site data) is
    // reporting that this device has no key, which is exactly true of it.
    return null;
  }
}

/**
 * Load this browser's device key for `address`, minting one on first use.
 *
 * The key is generated with `extractable: false`, so its private half can never be read back —
 * not by an exporter, not by the pairing ceremony, not by this module. That is what makes a
 * stolen account key insufficient: everything a thief can copy out of a backup is, by
 * construction, everything except this.
 */
export async function getOrCreateDeviceKey(address: string): Promise<DeviceKey> {
  const existing = await loadDeviceKey(address);
  if (existing) return existing;

  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
  const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
  const stored: StoredDeviceKey = { publicKey: new Uint8Array(raw), privateKey: pair.privateKey };
  await idbPut(DEVICE_STORE, deviceKeyRef(address), stored);
  return wrap(stored);
}

/**
 * Forget this browser's device key for `address`.
 *
 * Retiring a device on the relay is the half that matters for access; this is the local half, so
 * a signed-out browser stops holding a key it can no longer use. It does NOT retire the device —
 * a key discarded here while its record stays enrolled leaves the owner a phantom entry they
 * can see and remove, which is better than a silent deletion they cannot.
 */
export async function forgetDeviceKey(address: string): Promise<void> {
  try {
    await idbDelete(DEVICE_STORE, deviceKeyRef(address));
  } catch {
    // Nothing actionable: the key is unusable either way, and the record on the relay is what
    // governs access.
  }
}

// --- What an enrolled device signs to act on another device ---------------------------------
//
// Must match Go's deviceActionBytes (internal/core/identity/device.go). The parity vectors are
// TestParityVectorDeviceActions there and the matching block in deviceKey.test.ts.

const DEVICE_APPROVE_CTX = 'dmcn-device-approve-v1\0';
const DEVICE_RETIRE_CTX = 'dmcn-device-retire-v1\0';
const DEVICE_CHALLENGE_CTX = 'dmcn-device-challenge-v1\0';

/**
 * Build the bytes an enrolled device signs to act on another device.
 *
 * Four bindings, each closing a way of spending the signature elsewhere: the ADDRESS, so an
 * approval given on one mailbox is worthless on another; the SUBJECT device key, so vouching for
 * one device is not vouching for any other; the live challenge NONCE, so a signature captured
 * once cannot authorize the same action forever; and, on an approval, the TIME the approver
 * attests — which becomes the new device's enrolment date and therefore decides when it may
 * authorize a key rotation.
 *
 * `atSeconds` is undefined for actions carrying no attested time, and contributes nothing.
 */
function deviceActionBytes(ctx: string, address: string, subjectPub: Uint8Array, nonce: Uint8Array, atSeconds?: number): Uint8Array {
  const tag = new TextEncoder().encode(ctx);
  const addr = new TextEncoder().encode(address.toLowerCase());
  const timed = atSeconds !== undefined;
  const out = new Uint8Array(tag.length + addr.length + subjectPub.length + nonce.length + (timed ? 8 : 0));
  let at = 0;
  out.set(tag, at); at += tag.length;
  out.set(addr, at); at += addr.length;
  out.set(subjectPub, at); at += subjectPub.length;
  out.set(nonce, at); at += nonce.length;
  if (timed) {
    // Big-endian uint64, matching Go's binary.BigEndian.AppendUint64. Written through a DataView
    // rather than by hand so the two halves of the 64-bit value cannot be transposed.
    new DataView(out.buffer, out.byteOffset + at, 8).setBigUint64(0, BigInt(atSeconds), false);
  }
  return out;
}

/** The bytes an enrolled device signs to approve `subjectPub` joining `address` at `atSeconds`. */
export function deviceApprovalBytes(address: string, subjectPub: Uint8Array, nonce: Uint8Array, atSeconds: number): Uint8Array {
  return deviceActionBytes(DEVICE_APPROVE_CTX, address, subjectPub, nonce, atSeconds);
}

/**
 * The bytes an enrolled device signs to retire `subjectPub` from `address`.
 *
 * No attested time, unlike an approval: a retirement date only records when access ended and
 * feeds no later decision, so there is nothing for the signer to be trusted about.
 */
export function deviceRetirementBytes(address: string, subjectPub: Uint8Array, nonce: Uint8Array): Uint8Array {
  return deviceActionBytes(DEVICE_RETIRE_CTX, address, subjectPub, nonce);
}

/**
 * The bytes this device signs to answer a relay's challenge.
 *
 * Prefixed for the same reason the actions above are, and for a sharper one: the challenge is
 * chosen by the RELAY, and a device signs what it is handed. Signing the nonce raw would let a
 * hostile node serve deviceApprovalBytes(...) as the challenge and walk away with a signature
 * that enrols its own device on another relay — the owner's key vouching for an intruder, from a
 * login that looked entirely ordinary. Must match Go's identity.DeviceChallengeBytes.
 */
export function deviceChallengeBytes(nonce: Uint8Array): Uint8Array {
  const tag = new TextEncoder().encode(DEVICE_CHALLENGE_CTX);
  const out = new Uint8Array(tag.length + nonce.length);
  out.set(tag, 0);
  out.set(nonce, tag.length);
  return out;
}
