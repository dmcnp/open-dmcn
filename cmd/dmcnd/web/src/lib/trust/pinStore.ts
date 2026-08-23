// Device-local counterparty pins — the copy that DECIDES.
//
// Pins used to live only on the ContactRecord in the personal KV. That KV is sealed to
// the owner, so a relay cannot read or forge a pin; but it is served BY the relay, so it
// can withhold the contacts blob or serve an older sealed version the owner legitimately
// wrote earlier. Either one makes a pinned contact look unpinned, and an unpinned contact
// is re-pinned on next sight — to whatever key the directory is serving at that moment.
// The one defence built to survive a hostile fleet was hosted by it.
//
// So the pin is mirrored here, in this device's IndexedDB, and this copy wins. The KV
// copy is kept and still syncs pins across the owner's devices; reconcilePin decides what
// the KV is allowed to change. A KV pin may ADD a pin this device has never held, and may
// REPLACE one only by presenting a higher deliberate-repin sequence. It can never silently
// clear or downgrade a pin this device already holds.
//
// Honest limits, both inherent to per-device pinning rather than to this implementation:
//   - A context with an empty local store adopts the KV's pins on first sight. A brand new
//     device has no independent basis for a pin, so it must trust something once. Installed
//     app and browser tab are separate contexts (crypto/idb.ts), so each adopts once.
//   - A counterparty you have never corresponded with has no pin to compare against at all.
//     That gap is what a transparency log would close; a pin cannot.

import { PINS_STORE, idbGet, idbGetAll, idbPut, idbDelete } from '../crypto/idb';
import type { PinnedFacts } from './pinnedKey';

export interface LocalPin extends PinnedFacts {
  v: 1;
  owner: string;   // owning account address, lowercased
  address: string; // counterparty address, lowercased
  // seq counts DELIBERATE (re)pins by the owner, and is the rollback floor: a KV pin is
  // allowed to replace this one only with a strictly higher seq. A first pin is 1.
  seq: number;
  pinnedAt: number; // Unix ms, when THIS device recorded it
}

function norm(a: string): string {
  return a.trim().toLowerCase();
}

function pinId(owner: string, address: string): string {
  return `${norm(owner)}|${norm(address)}`;
}

// IndexedDB is unavailable in some privacy modes and can fail on quota. Every operation
// here degrades to the KV-only behaviour that preceded the local mirror rather than
// throwing into the UI — worse, but never worse than before, and never fail-open in the
// other direction (a read failure yields "no local pin", so the KV pin is used, exactly
// as it was used before this store existed).
export async function loadPin(owner: string, address: string): Promise<LocalPin | undefined> {
  try {
    return await idbGet<LocalPin>(PINS_STORE, pinId(owner, address));
  } catch {
    return undefined;
  }
}

// loadPins returns this account's pins keyed by lowercased counterparty address.
export async function loadPins(owner: string): Promise<Map<string, LocalPin>> {
  const out = new Map<string, LocalPin>();
  try {
    const all = await idbGetAll<LocalPin>(PINS_STORE);
    const me = norm(owner);
    for (const p of all) {
      if (p && p.owner === me && p.address) out.set(p.address, p);
    }
  } catch {
    // fall through to an empty map
  }
  return out;
}

export async function savePin(pin: LocalPin): Promise<void> {
  try {
    await idbPut(PINS_STORE, pinId(pin.owner, pin.address), pin);
  } catch {
    // best effort — the KV copy still carries the pin
  }
}

export async function deletePin(owner: string, address: string): Promise<void> {
  try {
    await idbDelete(PINS_STORE, pinId(owner, address));
  } catch {
    // best effort
  }
}

// makePin builds a local pin. seq defaults to 1 (a first pin); a deliberate re-pin passes
// the previous seq + 1.
export function makePin(owner: string, address: string, facts: PinnedFacts, seq = 1): LocalPin {
  return {
    v: 1,
    owner: norm(owner),
    address: norm(address),
    ...facts,
    seq: Math.max(1, Math.floor(seq)),
    pinnedAt: Date.now(),
  };
}

// PinAnomaly is a disagreement between the local pin and the KV copy that the owner
// should be able to see. Neither is proof of an attack — a device that wrote a pin while
// offline produces kv_missing too — but both are exactly what a rollback looks like, and
// they are invisible if nobody surfaces them.
export type PinAnomaly =
  | 'kv_missing'  // this device holds a pin the KV no longer carries
  | 'kv_conflict'; // the KV carries a DIFFERENT pin without a higher repin sequence

export interface PinDecision {
  // facts is what callers should treat as pinned: the local pin where there is one.
  facts?: PinnedFacts;
  seq: number;
  anomaly?: PinAnomaly;
  // adopt is a pin to write locally (the KV taught us something we didn't hold).
  adopt?: LocalPin;
  // heal asks the caller to re-push the local pin into the KV, repairing a copy that is
  // MISSING it. Only ever pushes what this device already decided, and deliberately not
  // set for a conflict — see reconcilePin.
  heal?: boolean;
}

// reconcilePin merges this device's pin with the KV's copy for one contact. `kv` is the
// pin carried on the ContactRecord (undefined when the row carries none), and kvSeq its
// recorded repin sequence (0/absent on records written before sequences existed).
export function reconcilePin(
  owner: string,
  address: string,
  local: LocalPin | undefined,
  kv: PinnedFacts | undefined,
  kvSeq = 0,
): PinDecision {
  const kvSeqN = Math.max(0, Math.floor(kvSeq)) || (kv ? 1 : 0);

  if (!local) {
    // Nothing held locally. Adopting the KV's pin is the one moment this device extends
    // trust to a fleet-served value — unavoidable for a device that has never seen this
    // counterparty, and it is why the adoption is recorded locally straight away.
    if (!kv?.ed25519Pub) return { seq: 0 };
    const adopt = makePin(owner, address, kv, kvSeqN);
    return { facts: kv, seq: kvSeqN, adopt };
  }

  const localFacts: PinnedFacts = {
    ed25519Pub: local.ed25519Pub,
    x25519Pub: local.x25519Pub,
    bridgeCapability: local.bridgeCapability,
    adminKeyCustody: local.adminKeyCustody,
  };

  if (!kv?.ed25519Pub) {
    // The KV lost a pin this device holds. Keep ours and push it back.
    return { facts: localFacts, seq: local.seq, anomaly: 'kv_missing', heal: true };
  }

  if (samePin(localFacts, kv)) {
    // Agreement. Carry the higher sequence so a repin recorded elsewhere isn't re-offered.
    return { facts: localFacts, seq: Math.max(local.seq, kvSeqN) };
  }

  if (kvSeqN > local.seq) {
    // Another of the owner's devices deliberately re-pinned (they re-verified after a
    // rotation). A higher sequence is the only thing that can move a held pin.
    const adopt = makePin(owner, address, kv, kvSeqN);
    return { facts: kv, seq: kvSeqN, adopt };
  }

  // Different pin, no higher sequence: a rollback, a substituted record, or two devices
  // that cold-adopted either side of a legitimate rotation. Local wins and the
  // disagreement is reported.
  //
  // Deliberately NOT healed. Writing our pin over theirs looks like repair but is a fight
  // this device cannot win or lose: if the other side is another of the owner's devices
  // holding a different first pin at the same sequence, both would keep overwriting each
  // other on every poll, and each would show a permanent conflict. Leaving the KV alone
  // keeps the disagreement visible and stable until the owner settles it by re-verifying
  // (allowlist bumps the sequence, which is the one thing that wins everywhere).
  return { facts: localFacts, seq: local.seq, anomaly: 'kv_conflict' };
}

export function samePin(a: PinnedFacts, b: PinnedFacts): boolean {
  return a.ed25519Pub === b.ed25519Pub
    && a.x25519Pub === b.x25519Pub
    && a.bridgeCapability === b.bridgeCapability
    && a.adminKeyCustody === b.adminKeyCustody;
}
