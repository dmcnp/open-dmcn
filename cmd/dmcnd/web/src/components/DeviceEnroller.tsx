// Keeping this browser on the account's device registry.
//
// A relay that has enrolled devices wants a signature from one of them alongside the account key,
// so a browser that is not on the registry cannot open the mailbox. This runs on every app open to
// make sure it is — and, on an account that has never had one, to be the first.
//
// That single pass covers three situations that would otherwise each need their own path:
//
//   - a fresh registration whose enrolment did not land, because the fleet was briefly away;
//   - an EXISTING account meeting the registry for the first time, which takes the same genesis
//     arm a new one does — there is no migration mode because an account with no enrolled devices
//     is simply an account whose first device is about to arrive;
//   - a device already enrolled, where the attempt costs one round trip and changes nothing.
//
// What it deliberately does NOT do is start a recovery request when the registry is claimed and
// this browser is not on it. Recovery admits an unapproved device on a delay that the owner's
// other devices can veto, and beginning that silently on every sign-in from an unfamiliar browser
// would bury the one signal that makes a hostile request noticeable.
//
// It renders nothing.

import { useEffect } from 'react';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { ensureDeviceEnrolled, signerFor } from '../lib/api/deviceRegistry';

export function DeviceEnroller({ address, keys, onNeedsApproval }: {
  address: string;
  keys: WorkingKeys;
  /** Called when this browser is shut out: the remedy is pairing, or the recovery path. */
  onNeedsApproval?: () => void;
}) {
  useEffect(() => {
    if (!address || !keys) return;
    let cancelled = false;
    void (async () => {
      const result = await ensureDeviceEnrolled(signerFor(keys));
      if (cancelled) return;
      if (result.state === 'needs-approval') onNeedsApproval?.();
      // 'unavailable' changes nothing on screen — a fleet that cannot be reached right now says
      // nothing about whether this device belongs, and the next app open asks again — but it is
      // said out loud. A device that never enrols is invisible until someone tries to re-key and
      // is told they cannot, which is a long way from the thing that actually failed.
      if (result.state === 'unavailable') {
        console.warn('this device could not enrol on the mailbox; retrying on the next open', result.error);
      }
    })();
    return () => { cancelled = true; };
  }, [address, keys, onNeedsApproval]);

  return null;
}
