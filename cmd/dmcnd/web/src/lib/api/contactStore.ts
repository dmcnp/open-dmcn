// ContactStore backs the address book with the personal storage substrate: one record per
// contact under "contacts/<id>". Per-record LWW — concurrent edits to different contacts never
// collide.
//
// Synced across the owner's devices: PersonalStore is backed by the relay's personal storage,
// with each record sealed to the owner before it leaves the browser. On a relay that offers no
// storage it falls back to device-local IndexedDB — see personalStore.ts.
//
// The PINNED fields here are the sync copy only. Because this record is relay-served, the
// authoritative pin lives in device-local IndexedDB (trust/pinStore.ts); see the note on
// ContactRecord.

import { PersonalStore, StorageConflictError, type StorageEntry } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';
import type { PinnedFacts } from '../trust/pinnedKey';
import { toBase64, toHex } from '../crypto/keys';

// TrustProvenance records HOW the owner confirmed a contact's identity — the
// allowlist "trust provenance" of whitepaper §14.1.1, in descending strength.
// A ContactRecord with a provenance IS an allowlist entry; one without is a plain
// address-book row (legacy v1 records, or contacts added without a trust decision).
export type TrustProvenance =
  | 'in_person'        // direct key exchange, face to face
  | 'fingerprint'      // out-of-band fingerprint comparison
  | 'network_vouched'  // vouched for by ≥N of the owner's Verified contacts
  | 'org_verified'     // shares a verified organisational (domain) identity
  | 'user_approved';   // first-message approval (weakest)

export interface ContactRecord {
  v: number;
  address: string;
  name: string;
  fingerprint: string;
  notes?: string;
  updatedAt: number;
  deviceId: string; // hex
  // §14.1 allowlist fields (v2). provenance present ⇒ this contact is allowlisted.
  provenance?: TrustProvenance;
  // Pinned keys (base64 std, matching IdentityLookupResponse.ed25519_pub/x25519_pub)
  // captured at allowlisting, so a later unsigned key change is detectable
  // (§14.1.2). Absent on legacy v1 records ⇒ key-change detection disabled until
  // the key is lazily pinned (see pinContactKey).
  //
  // These are the SYNC copy of the pin, not the authoritative one. This record is
  // served by the relay, which can withhold or roll it back; the copy that decides
  // lives in device-local IndexedDB (trust/pinStore.ts) and useContacts reconciles
  // the two before anything downstream reads them.
  ed25519Pub?: string;
  x25519Pub?: string;
  pinnedAt?: number; // Unix ms when the keys were pinned
  // v3 pinned properties. Not keys, but not owner-signed either: adminKeyCustody is
  // domain DAR policy an operator controls unilaterally, so a silent flip is exactly
  // the change a key comparison cannot see. See trust/pinnedKey.ts PinnedFacts.
  bridgeCapability?: boolean;
  adminKeyCustody?: boolean;
  // pinSeq counts DELIBERATE re-pins by the owner (re-verifying after a rotation). It
  // is the only thing that lets a KV pin replace one a device already holds, so it
  // must only ever increase. Absent on v1/v2 records ⇒ treated as 1.
  pinSeq?: number;
}

// contactId derives a stable, key-safe id from the (lowercased) address, so adding
// the same address twice updates one record. base64url keeps it within the KV key
// charset (addresses contain '@' which the relay rejects as a raw key).
export function contactId(address: string): string {
  const b64 = toBase64(new TextEncoder().encode(address.trim().toLowerCase()));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function contactKey(address: string): string {
  return 'contacts/' + contactId(address);
}

export class ContactStore {
  private store: PersonalStore;
  private deviceHex: string;

  constructor(keys: WorkingKeys) {
    this.store = new PersonalStore(keys);
    this.deviceHex = toHex(keys.deviceId);
  }

  async list(): Promise<ContactRecord[]> {
    const entries: StorageEntry<ContactRecord>[] = await this.store.list<ContactRecord>('contacts/');
    return entries.map(e => e.value);
  }

  // put creates or updates a contact (keyed by address, so idempotent per address).
  put(c: Omit<ContactRecord, 'v' | 'updatedAt' | 'deviceId'>): Promise<number> {
    const rec: ContactRecord = { v: 3, ...c, updatedAt: Date.now(), deviceId: this.deviceHex };
    return this.store.put(contactKey(c.address), rec);
  }

  // update applies a partial edit — the owner's chosen name, notes — to an existing
  // contact WITHOUT touching its trust fields, so renaming never drops the record's
  // provenance or pinned keys (which a blind put() of the form fields would).
  // Compare-and-swap, with one retry if another device wrote in between.
  async update(address: string, patch: Partial<Pick<ContactRecord, 'name' | 'notes'>>): Promise<ContactRecord> {
    for (let attempt = 0; ; attempt++) {
      const entry = await this.store.get<ContactRecord>(contactKey(address));
      if (!entry) throw new Error('Contact no longer exists');
      const rec: ContactRecord = {
        ...entry.value,
        ...patch,
        v: 3,
        updatedAt: Date.now(),
        deviceId: this.deviceHex,
      };
      try {
        await this.store.put(contactKey(address), rec, entry.version);
        return rec;
      } catch (e) {
        if (e instanceof StorageConflictError && attempt === 0) continue;
        throw e;
      }
    }
  }

  // pinContactKey lazily records the sender's public keys on an existing contact the
  // first time we see a signature-verified message whose directory key matches — so a
  // later unsigned key change becomes detectable (§14.1.2). It is a no-op if the
  // address is not a contact or already has a pinned key (the caller handles a
  // mismatch as a key change, not a re-pin). Compare-and-swap guards concurrent edits.
  //
  // This writes the SYNC copy only. The caller (useContacts.pinKey) writes the local,
  // authoritative copy as well; a failure here leaves the pin held on this device and
  // simply not yet shared with the owner's others.
  pinContactKey(address: string, facts: PinnedFacts): Promise<void> {
    return this.writePin(address, facts, 1, 'lazy');
  }

  // repinContactKey is the DELIBERATE re-pin: the owner re-verified a counterparty after
  // a rotation, so the held pin is replaced and its sequence advanced. The sequence is
  // what allows the new pin to travel to the owner's other devices at all — without a
  // higher seq those devices keep what they hold and report a conflict (pinStore.ts).
  repinContactKey(address: string, facts: PinnedFacts, seq: number): Promise<void> {
    return this.writePin(address, facts, seq, 'force');
  }

  // healPin re-pushes a pin this device holds into a KV row that lost it or drifted,
  // WITHOUT advancing the sequence — it repairs the copy, it does not make a new
  // trust decision.
  healPin(address: string, facts: PinnedFacts, seq: number): Promise<void> {
    return this.writePin(address, facts, seq, 'force');
  }

  private async writePin(
    address: string,
    facts: PinnedFacts,
    seq: number,
    mode: 'lazy' | 'force',
  ): Promise<void> {
    const entry = await this.store.get<ContactRecord>(contactKey(address));
    if (!entry) return;
    if (mode === 'lazy' && entry.value.ed25519Pub) return;
    const rec: ContactRecord = {
      ...entry.value,
      v: 3,
      ed25519Pub: facts.ed25519Pub,
      x25519Pub: facts.x25519Pub,
      bridgeCapability: facts.bridgeCapability,
      adminKeyCustody: facts.adminKeyCustody,
      pinSeq: Math.max(1, Math.floor(seq)),
      pinnedAt: Date.now(),
      updatedAt: Date.now(),
      deviceId: this.deviceHex,
    };
    try {
      await this.store.put(contactKey(address), rec, entry.version);
    } catch {
      // A concurrent write won the CAS; skip — the next receive re-pins if needed.
    }
  }

  delete(address: string): Promise<void> {
    return this.store.delete(contactKey(address));
  }
}
