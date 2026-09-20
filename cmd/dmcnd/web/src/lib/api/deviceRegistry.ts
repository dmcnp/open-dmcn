// The device registry, from the browser's side.
//
// Which devices an account has enrolled, and when. A relay that has enrolled devices wants a
// signature from one of them alongside the account key, so this is what decides whether a browser
// can open a mailbox at all.
//
// Enrolment is always performed by a device ALREADY on the mailbox, never by the newcomer. An
// approval is signed over the live challenge nonce, and only a party already authenticated there
// can obtain one — a newcomer given a signed blob to spend later is exactly what that binding
// rules out. In pairing, the approving device enrols the newcomer in the same step that hands
// over the account keys.
import { deployment } from '@deployment';
import { postJSONAs } from './client';
import { getOrCreateDeviceKey, loadDeviceKey, deviceChallengeBytes } from '../crypto/deviceKey';
import { deviceApprovalBytes, deviceRetirementBytes } from '../crypto/deviceKey';
import { signWithKey } from '../crypto/sign';
import { fromBase64, toBase64 } from '../crypto/keys';
import type { WorkingKeys } from '../crypto/workingKeys';

/**
 * Whatever can sign for the account right now.
 *
 * Deliberately narrower than WorkingKeys, because the account key reaches this module in two
 * shapes and the difference is not this module's business: a resident non-extractable handle on
 * an unlocked session, or a raw seed held for the length of one operation during registration.
 * Both sign; nothing here needs to know which.
 */
export interface AccountSigner {
  address: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** Adapt unlocked working keys to an AccountSigner — the ordinary case. */
export function signerFor(keys: WorkingKeys): AccountSigner {
  return { address: keys.address, sign: (data) => signWithKey(keys.ed25519Sign, data) };
}

/** One enrolled device as the relay reports it. The label stays sealed to the owner. */
export interface DeviceRecord {
  public: string;
  enrolled_at: number;
  retired_at?: number;
  /** Set while a recovery enrolment waits out its delay: on the mailbox, visible, unable to act. */
  eligible_at?: number;
  /**
   * The domain's attestation of this device, as supplied at enrolment (base64).
   *
   * Read back here rather than kept in the browser: a key rotation needs it months after the
   * enrolment that produced it, and the registry is where that enrolment already lives. Absent
   * on a device enrolled without one — such a device reads mail and cannot re-key.
   */
  credential?: string;
  sealed_label?: string;
}

/** This browser's own entry in the registry, or null when it is not enrolled. */
export async function thisDevice(address: string, account: AccountSigner): Promise<DeviceRecord | null> {
  const key = await loadDeviceKey(address);
  if (!key) return null;
  const mine = toBase64(key.publicKey);
  return (await listDevices(account)).find(d => d.public === mine && !d.retired_at) ?? null;
}

interface ChallengeResp { correlation_id: string; nonce: string }

/**
 * Run one device op: challenge, then complete with both signatures over the nonce.
 *
 * `authorize` produces the op's own authorization — the approval or retirement — over the same
 * nonce the gate proof covers. Two signatures by the same key over different bytes: one says the
 * request comes from an enrolled device, the other says what that device is asking for.
 */
async function deviceOp<T>(
  account: AccountSigner,
  challenge: Record<string, unknown>,
  authorize?: (nonce: Uint8Array, devicePub: Uint8Array) => Promise<Uint8Array>,
  approvedAt?: number,
): Promise<T> {
  const ch = await postJSONAs<ChallengeResp>(undefined, '/api/v1/mailbox/challenge', challenge);
  const nonce = fromBase64(ch.nonce);

  const device = await loadDeviceKey(account.address);
  const body: Record<string, unknown> = {
    correlation_id: ch.correlation_id,
    signature: toBase64(await account.sign(nonce)),
  };
  if (device) {
    body.device_public = toBase64(device.publicKey);
    body.device_signature = toBase64(await device.sign(deviceChallengeBytes(nonce)));
    if (authorize) {
      body.approver_signature = toBase64(await authorize(nonce, device.publicKey));
    }
  }
  if (approvedAt !== undefined) body.approved_at = approvedAt;
  return postJSONAs<T>(undefined, '/api/v1/mailbox/complete', body);
}

/**
 * Enrol `devicePub` on this account, vouched for by the device running this code.
 *
 * `atSeconds` is the moment this device attests the newcomer joined, and becomes its enrolment
 * date — which later decides when it may authorize a key rotation. The relay bounds it: never
 * before this device's own enrolment, never in the future.
 */
export async function enrolDevice(
  address: string,
  account: AccountSigner,
  devicePub: Uint8Array,
  atSeconds: number,
  sealedLabel?: Uint8Array,
  credential?: Uint8Array,
): Promise<{ device: DeviceRecord; genesis: boolean }> {
  // Where the deployment attests devices, the credential's date is the one that counts: the relay
  // requires the two to agree, and the attested time is what a later key rotation is judged
  // against. Taking the issuer's own value rather than proposing one leaves no room to ask for a
  // backdated attestation.
  if (!credential) {
    const attested = await attestDevice(address, devicePub);
    if (attested) {
      credential = attested.credential;
      atSeconds = attested.issuedAt;
    }
  }
  return deviceOp(
    account,
    {
      op: 'device_enroll',
      device_public: toBase64(devicePub),
      ...(sealedLabel ? { device_label: toBase64(sealedLabel) } : {}),
      ...(credential ? { device_credential: toBase64(credential) } : {}),
    },
    async (nonce) => {
      const approver = await loadDeviceKey(address);
      if (!approver) throw new Error('this device is not enrolled, so it cannot approve another');
      return approver.sign(deviceApprovalBytes(address, devicePub, nonce, atSeconds));
    },
    atSeconds,
  );
}

/**
 * Ask this deployment to attest a device, if it can.
 *
 * Null is an ordinary answer, not a failure: a deployment with no online issuer signs these by
 * hand, and a device enrols perfectly well without one. Failures are swallowed for the same
 * reason — an attestation that could not be obtained must not stop a device joining the mailbox,
 * because being unable to read mail is a far worse outcome than being unable to re-key.
 */
async function attestDevice(address: string, devicePub: Uint8Array): Promise<{ credential: Uint8Array; issuedAt: number } | null> {
  if (!deployment.deviceCredential) return null;
  try {
    return await deployment.deviceCredential(address, devicePub);
  } catch {
    return null;
  }
}

/** Every device on this account, tombstones included — a removal is what an owner needs to see. */
export async function listDevices(account: AccountSigner): Promise<DeviceRecord[]> {
  const res = await deviceOp<{ devices: DeviceRecord[] }>(account, { op: 'device_list' });
  return res.devices ?? [];
}

/**
 * Retire `devicePub`, asked for by the device running this code.
 *
 * It must be a DIFFERENT device: the relay refuses a device retiring itself, which is what
 * guarantees a mailbox always keeps at least one enrolled device.
 */
export async function retireDevice(address: string, account: AccountSigner, devicePub: Uint8Array): Promise<DeviceRecord> {
  const res = await deviceOp<{ device: DeviceRecord }>(
    account,
    { op: 'device_retire', device_public: toBase64(devicePub) },
    async (nonce) => {
      const signer = await loadDeviceKey(address);
      if (!signer) throw new Error('this device is not enrolled, so it cannot retire another');
      return signer.sign(deviceRetirementBytes(address, devicePub, nonce));
    },
  );
  return res.device;
}

/**
 * What an attempt to put THIS browser on the mailbox found.
 *
 * `enrolled` covers both outcomes that need no further action: this device created the registry,
 * or it was already on it. `needs-approval` means the registry is claimed and this device is not
 * in it — the remedy is pairing from a device that is, or the recovery path, and neither is
 * something to start without the owner asking.
 */
export type EnrolmentState =
  | { state: 'enrolled'; genesis: boolean }
  | { state: 'needs-approval' }
  | { state: 'unavailable'; error: unknown };

/**
 * Put this browser on the mailbox if it can be, and report what it found.
 *
 * The attempt IS the probe, and it has to be: knowing whether this device is enrolled would mean
 * listing the registry, and listing is itself gated on being enrolled. So we ask to join, and the
 * relay's answer distinguishes the three states — created it, already on it, or shut out.
 *
 * The genesis case is what a fresh registration takes, and equally what an existing account takes
 * the first time it meets the registry. One path, no migration mode: an account with no enrolled
 * devices is an account whose first device is about to arrive, however old the account is.
 *
 * It deliberately does NOT fall back to the recovery path when shut out. Recovery admits an
 * unapproved device on a delay that other devices can veto, and starting that silently — on every
 * sign-in from an unfamiliar browser — would turn a deliberate act into background noise, which
 * is exactly how a real hostile request would go unnoticed.
 */
export async function ensureDeviceEnrolled(account: AccountSigner): Promise<EnrolmentState> {
  try {
    const device = await getOrCreateDeviceKey(account.address);
    const attested = await attestDevice(account.address, device.publicKey);
    const res = await deviceOp<{ genesis: boolean }>(account, {
      op: 'device_enroll',
      device_public: toBase64(device.publicKey),
      ...(attested ? { device_credential: toBase64(attested.credential) } : {}),
    }, undefined, attested?.issuedAt);
    return { state: 'enrolled', genesis: res.genesis };
  } catch (err) {
    return classifyEnrolment(err);
  }
}

/**
 * Turn a failed enrolment into the state it actually represents.
 *
 * Two of the relay's answers are states rather than failures, and reading either wrongly is
 * quiet: "already enrolled" taken as an error shows a working device as shut out on every open,
 * while "needs approval" taken as success lets a browser believe it is fine until its first
 * mailbox call fails with nothing to explain it.
 *
 * Matched on the message because the mailbox proxy forwards the relay's own words. A code would
 * be sturdier and is worth adding when that proxy grows structured errors; until then the strings
 * are pinned by tests on both sides of the boundary.
 */
export function classifyEnrolment(err: unknown): EnrolmentState {
  if (err instanceof Error) {
    // Both phrases contain the word "already", and a loose match on it reads a shut-out browser
    // as a working one — so each match is the narrowest phrase unique to its answer. The relay
    // strings are relay.ErrDeviceApprovalRequired and the "already enrolled" refusal in
    // handleDeviceEnroll; the tests below carry them verbatim.
    if (err.message.includes('needs approval from a device')) return { state: 'needs-approval' };
    if (err.message.includes('this device is already enrolled')) return { state: 'enrolled', genesis: false };
  }
  return { state: 'unavailable', error: err };
}
