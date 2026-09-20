// The two signatures a mailbox request carries, and where they come from.
//
// The ACCOUNT key signs the challenge nonce, as it always has — that says whose mailbox this is.
// The DEVICE key signs that same nonce under a context tag of its own — that says the request
// comes from somewhere the owner approved. A relay that has enrolled devices demands both, so an
// account key lifted out of a backup export opens nothing on its own.
//
// The tag is what stops the relay choosing what this device signs. The challenge is its to pick,
// and an untagged signature over arbitrary bytes is a signature over whatever message those bytes
// happen to spell — an approval enrolling someone else's device, for instance.
//
// Both are made here, in the browser. The backend relays them untouched and holds neither key,
// which is what keeps it a proxy rather than a party to the proof.
import { loadDeviceKey, deviceChallengeBytes } from '../crypto/deviceKey';
import { signWithKey } from '../crypto/sign';
import { fromBase64, toBase64 } from '../crypto/keys';
import type { WorkingKeys } from '../crypto/workingKeys';

/** The proof fields the /api/v1/mailbox/complete body carries. */
export interface MailboxProofFields {
  signature: string;
  device_public?: string;
  device_signature?: string;
}

/**
 * Sign a mailbox challenge with the account key, and with this device's key when it has one.
 *
 * A browser that has never enrolled has no device key, and sends only the account signature —
 * which is exactly right while the mailbox has no enrolled devices, and is refused by the relay
 * once it does. Sending nothing rather than something invalid keeps that refusal legible: the
 * answer is "this device is not enrolled", not "your signature is wrong".
 */
export async function mailboxProof(keys: WorkingKeys, nonceB64: string): Promise<MailboxProofFields> {
  const nonce = fromBase64(nonceB64);
  const out: MailboxProofFields = { signature: toBase64(await signWithKey(keys.ed25519Sign, nonce)) };

  const device = await loadDeviceKey(keys.address);
  if (device) {
    out.device_public = toBase64(device.publicKey);
    out.device_signature = toBase64(await device.sign(deviceChallengeBytes(nonce)));
  }
  return out;
}
