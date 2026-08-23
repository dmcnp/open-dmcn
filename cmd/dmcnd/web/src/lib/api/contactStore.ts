// ContactStore backs the address book with the personal storage substrate: one record per
// contact under "contacts/<id>". Per-record LWW — concurrent edits to different contacts never
// collide.
//
// Synced across the owner's devices: PersonalStore is backed by the relay's personal storage,
// with each record sealed to the owner before it leaves the browser. On a relay that offers no
// storage it falls back to device-local IndexedDB — see personalStore.ts.

import { PersonalStore, type StorageEntry } from './personalStore';
import type { WorkingKeys } from '../crypto/workingKeys';
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
  ed25519Pub?: string;
  x25519Pub?: string;
  pinnedAt?: number; // Unix ms when the keys were pinned
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
    const rec: ContactRecord = { v: 2, ...c, updatedAt: Date.now(), deviceId: this.deviceHex };
    return this.store.put(contactKey(c.address), rec);
  }

  // pinContactKey lazily records the sender's public keys on an existing contact the
  // first time we see a signature-verified message whose directory key matches — so a
  // later unsigned key change becomes detectable (§14.1.2). It is a no-op if the
  // address is not a contact or already has a pinned key (the caller handles a
  // mismatch as a key change, not a re-pin). Compare-and-swap guards concurrent edits.
  async pinContactKey(address: string, ed25519Pub: string, x25519Pub: string): Promise<void> {
    const entry = await this.store.get<ContactRecord>(contactKey(address));
    if (!entry || entry.value.ed25519Pub) return;
    const rec: ContactRecord = {
      ...entry.value,
      v: 2,
      ed25519Pub,
      x25519Pub,
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
