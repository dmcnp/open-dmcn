import { createContext, useContext, useState, useCallback, useEffect, useMemo, useRef, ReactNode, createElement } from 'react';
import { ContactStore, type ContactRecord, type TrustProvenance } from '../api/contactStore';
import { contactFacts, type PinnedFacts, absentIdentityFacts } from '../trust/pinnedKey';
import { loadPin, loadPins, savePin, deletePin, makePin, reconcilePin, type PinAnomaly } from '../trust/pinStore';
import { STORAGE_POLL_INTERVAL_MS } from '../config';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';
import { usePolling } from './usePolling';

export interface Contact {
  address: string;
  name: string;
  fingerprint: string;
}

const LEGACY_KEY = 'dmcn_contacts';

function normAddr(a: string): string {
  return a.trim().toLowerCase();
}

function byName(a: Contact, b: Contact): number {
  return (a.name || a.address).localeCompare(b.name || b.address);
}

// recordsSig is a content signature over the fields consumers care about, so a poll
// that returns an equal list doesn't churn `records` identity (which would ripple
// into every consumer — inbox categorization, the open reader's trust badge, etc.).
function recordsSig(list: ContactRecord[]): string {
  return list
    .map(r => [
      normAddr(r.address), r.v, r.updatedAt, r.name, r.fingerprint, r.provenance ?? '',
      r.ed25519Pub ?? '', r.x25519Pub ?? '',
      r.bridgeCapability ? '1' : '', r.adminKeyCustody ? '1' : '', r.pinSeq ?? 0,
    ].join('|'))
    .sort()
    .join('\n');
}

// readLegacyContacts returns the device-local contact list, or null when there is none or it
// cannot be read (storage blocked, unparsable) — the two cases migrateLegacy treats alike.
function readLegacyContacts(): Contact[] | null {
  try {
    const raw = localStorage.getItem(LEGACY_KEY);
    return raw ? (JSON.parse(raw) as Contact[]) : null;
  } catch {
    return null;
  }
}

// migrateLegacy imports any device-local (localStorage) contacts into the synced
// store once, then clears them — so upgrading users don't lose their address book.
async function migrateLegacy(store: ContactStore): Promise<void> {
  const saved = readLegacyContacts();
  if (saved === null) return; // nothing stored, or unreadable — leave it alone
  if (!Array.isArray(saved) || saved.length === 0) {
    localStorage.removeItem(LEGACY_KEY);
    return;
  }
  try {
    for (const c of saved) {
      await store.put({ address: c.address, name: c.name, fingerprint: c.fingerprint });
    }
    localStorage.removeItem(LEGACY_KEY); // only after all imported
  } catch {
    // leave localStorage in place; retry on a later mount
  }
}

// applyLocalPins reconciles the KV's contact list against this device's pin store and
// returns records whose pinned facts are the LOCAL ones.
//
// Doing the substitution HERE, once, is what makes the local copy authoritative for the
// whole app: categorizeSender, evaluateSenderTrust and the composer's send gate all read
// pins off a ContactRecord, so they inherit the local pin without any of them having to
// remember to ask for it. Reconciling at each call site instead would mean every future
// consumer is one forgotten lookup away from trusting the relay's copy again.
async function applyLocalPins(
  owner: string,
  store: ContactStore,
  list: ContactRecord[],
): Promise<{ records: ContactRecord[]; alerts: PinAlert[] }> {
  const localPins = await loadPins(owner);
  const records: ContactRecord[] = [];
  const alerts: PinAlert[] = [];
  for (const rec of list) {
    const decision = reconcilePin(
      owner,
      rec.address,
      localPins.get(normAddr(rec.address)),
      contactFacts(rec),
      rec.pinSeq ?? 0,
    );
    if (decision.adopt) void savePin(decision.adopt);
    if (decision.anomaly) alerts.push({ address: rec.address, anomaly: decision.anomaly });
    if (decision.heal && decision.facts) {
      // Repair the KV copy from ours. Never the reverse, and never a new decision.
      void store.healPin(rec.address, decision.facts, decision.seq).catch(() => {});
    }
    records.push(decision.facts ? { ...rec, ...decision.facts, pinSeq: decision.seq } : rec);
  }
  return { records, alerts };
}

function alertsSig(list: PinAlert[]): string {
  return list.map(a => `${normAddr(a.address)}|${a.anomaly}`).sort().join('\n');
}

// AllowlistInput is a first-message-approval (or manual) allowlist entry with its
// trust provenance and the sender's pinned keys (§14.1).
export interface AllowlistInput {
  address: string;
  name: string;
  fingerprint: string;
  provenance: TrustProvenance;
  ed25519Pub?: string; // base64 std
  x25519Pub?: string;  // base64 std
  bridgeCapability?: boolean;
  adminKeyCustody?: boolean;
  // Set when the owner is confirming that this address has NO DMCN identity (see
  // trust/pinnedKey.ts). Mutually exclusive with the key fields in practice.
  noIdentity?: boolean;
}

// PinAlert reports a disagreement between this device's pin and the KV copy, found
// while reconciling. Surfaced rather than silently resolved: local always wins the
// resolution, but "the relay handed back a contacts blob without the pin I took" is
// precisely the shape of the rollback the local mirror exists to catch, and it is
// invisible unless something says so.
export interface PinAlert {
  address: string;
  anomaly: PinAnomaly;
}

interface ContactsContextValue {
  contacts: Contact[];
  // ready is false until the first load resolves — lets consumers avoid acting on
  // an empty list (e.g. gating a message) before contacts are known.
  ready: boolean;
  contactByAddress: (address: string) => ContactRecord | undefined;
  // nameFor is THE display-name resolver for the whole app: the owner's chosen
  // contact name when there is one, else the raw address. Addresses are the only
  // identity DMCN carries on the wire (a sender can't claim a name), so the address
  // book is the single naming source — one helper keeps lists, the reader and
  // compose showing the same label for the same person.
  nameFor: (address: string) => string;
  addContact: (contact: Contact) => Promise<void>;
  // updateContact edits an existing contact in place (name/notes), preserving its
  // trust provenance and pinned keys.
  updateContact: (address: string, patch: { name?: string; notes?: string }) => Promise<void>;
  allowlist: (input: AllowlistInput) => Promise<void>;
  pinKey: (address: string, facts: PinnedFacts) => Promise<void>;
  removeContact: (address: string) => Promise<void>;
  // pinAlerts reports contacts whose device-local pin disagrees with the KV copy.
  // Empty in normal operation.
  pinAlerts: PinAlert[];
}

const ContactsContext = createContext<ContactsContextValue | null>(null);

// ContactsProvider owns the address book (synced + E2E) as ONE shared instance for
// the whole app, so consumers (inbox, reader, nav) read already-loaded data instead
// of each re-fetching on mount (which caused the reader's trust flicker). It keeps
// the FULL records (provenance + pinned keys) plus the lightweight projection.
export function ContactsProvider({ children }: { children: ReactNode }) {
  const { keys } = useKeys();
  const { sessionToken, isAuthenticated } = useAuth();
  const [records, setRecords] = useState<ContactRecord[]>([]);
  const [pinAlerts, setPinAlerts] = useState<PinAlert[]>([]);
  const [ready, setReady] = useState(false);
  const storeRef = useRef<ContactStore | null>(null);
  // The account these contacts (and their pins) belong to. Pins are namespaced by owner
  // so several accounts unlocked in one tab never read each other's.
  const ownerRef = useRef<string>('');
  const loadRef = useRef<() => void>(() => {});

  // Gate on the account session (token + auth), not just keys: during device
  // pairing `keys` is installed a beat BEFORE the real account session token is
  // swapped in for the throwaway ephemeral one, so loading on `keys` alone would
  // race the swap, fetch an empty/unauthorized contacts list, and never retry —
  // leaving already-trusted senders miscategorized as pending. Re-running when the
  // token/auth land (as MessagesProvider does) closes that window.
  useEffect(() => {
    if (!keys || !sessionToken || !isAuthenticated) return;
    const store = new ContactStore(keys);
    storeRef.current = store;
    const owner = keys.address;
    ownerRef.current = owner;

    let cancelled = false;
    const load = () =>
      store.list()
        .then(async (list: ContactRecord[]) => {
          if (cancelled) return;
          // Every poll re-reconciles against the local pin store, so a KV copy that
          // loses or changes a pin between polls is caught then rather than only at
          // session start.
          const merged = await applyLocalPins(owner, store, list);
          if (cancelled) return;
          // Compare against the CURRENT records, never a side-ref: this effect
          // re-runs whenever the session token is renewed (SessionRenewer re-mints
          // it silently on a 401), and its cleanup empties `records`. A remembered
          // signature would survive that reset, make the reload look like "no
          // change", and leave the address book empty for the rest of the session —
          // every sender then reads as an unknown/new one until a page reload.
          setRecords(prev => (recordsSig(prev) === recordsSig(merged.records) ? prev : merged.records));
          setPinAlerts(prev => (alertsSig(prev) === alertsSig(merged.alerts) ? prev : merged.alerts));
        })
        .catch(() => { /* transient */ })
        .finally(() => { if (!cancelled) setReady(true); });

    loadRef.current = load;
    migrateLegacy(store).finally(load);


    return () => {
      cancelled = true;
      storeRef.current = null;
      ownerRef.current = '';
      loadRef.current = () => {};
      setReady(false);
      setRecords([]);
      setPinAlerts([]);
    };
  }, [keys, sessionToken, isAuthenticated]);

  usePolling(() => loadRef.current(), STORAGE_POLL_INTERVAL_MS);

  const contacts = useMemo<Contact[]>(
    () => records.map(r => ({ address: r.address, name: r.name, fingerprint: r.fingerprint })).sort(byName),
    [records],
  );

  const recordMap = useMemo(() => {
    const m = new Map<string, ContactRecord>();
    for (const r of records) m.set(normAddr(r.address), r);
    return m;
  }, [records]);

  const contactByAddress = useCallback(
    (address: string): ContactRecord | undefined => recordMap.get(normAddr(address)),
    [recordMap],
  );

  // A record whose name was never set (or was seeded with the address itself, as the
  // reader's allowlist action does) carries no naming information — fall back to the
  // address so the UI never renders a "name" that is just the address twice.
  const nameFor = useCallback((address: string): string => {
    const name = recordMap.get(normAddr(address))?.name?.trim();
    if (!name || normAddr(name) === normAddr(address)) return address;
    return name;
  }, [recordMap]);

  const addContact = useCallback(async (contact: Contact) => {
    if (!storeRef.current) return;
    await storeRef.current.put(contact);
    setRecords(prev => [
      ...prev.filter(c => normAddr(c.address) !== normAddr(contact.address)),
      { v: 2, ...contact, updatedAt: Date.now(), deviceId: '' },
    ]);
  }, []);

  const updateContact = useCallback(async (address: string, patch: { name?: string; notes?: string }) => {
    if (!storeRef.current) return;
    const rec = await storeRef.current.update(address, patch);
    setRecords(prev => prev.map(c => (normAddr(c.address) === normAddr(address) ? rec : c)));
  }, []);

  // allowlist adds/updates a contact WITH a trust provenance + pinned keys — the
  // "I trust the sender" first-message-approval action (§14.2.1).
  const allowlist = useCallback(async (input: AllowlistInput) => {
    const store = storeRef.current;
    const owner = ownerRef.current;
    if (!store || !owner) return;
    let pinSeq: number | undefined;
    // A confirmed ABSENCE of an identity is pinned exactly like a present one: it is the
    // owner deciding what this address currently is, and it must survive so a key appearing
    // later reads as a change rather than a first sighting.
    if (input.ed25519Pub || input.noIdentity) {
      const facts: PinnedFacts = input.noIdentity
        ? absentIdentityFacts()
        : {
            ed25519Pub: input.ed25519Pub!,
            x25519Pub: input.x25519Pub ?? '',
            bridgeCapability: input.bridgeCapability === true,
            adminKeyCustody: input.adminKeyCustody === true,
          };
      // Allowlisting is the owner deliberately deciding to trust these keys, and it is
      // the ONLY action allowed to replace a pin this device already holds — it is the
      // remedy the composer points at ("remove them and add them again"). Advancing the
      // sequence is what carries that decision to the owner's other devices; without it
      // they would keep the superseded pin and report a conflict forever.
      pinSeq = ((await loadPin(owner, input.address))?.seq ?? 0) + 1;
      await savePin(makePin(owner, input.address, facts, pinSeq));
    }
    await store.put({ ...input, pinSeq });
    setRecords(prev => [
      ...prev.filter(c => normAddr(c.address) !== normAddr(input.address)),
      { v: 3, ...input, pinSeq, updatedAt: Date.now(), deviceId: '' },
    ]);
    setPinAlerts(prev => prev.filter(a => normAddr(a.address) !== normAddr(input.address)));
  }, []);

  // pinKey lazily records a contact's public keys the first time we can confirm them
  // (§14.1.2), so a later unsigned key change is detectable. No-op if not a contact
  // or already pinned.
  const pinKey = useCallback(async (address: string, facts: PinnedFacts) => {
    const store = storeRef.current;
    const owner = ownerRef.current;
    if (!store || !owner || !facts.ed25519Pub) return;
    // A lazy pin never overwrites one this device already holds — that is what makes it
    // a pin. Checking the LOCAL store (not the record) is the point: a KV copy stripped
    // of its pin would otherwise make an already-pinned contact look pinnable again,
    // which is exactly the re-pin-to-the-attacker's-key path this store closes.
    if (await loadPin(owner, address)) return;
    await savePin(makePin(owner, address, facts, 1));
    // The KV copy is sync only, so a failure here costs cross-device propagation, not
    // the pin itself.
    await store.pinContactKey(address, facts).catch(() => {});
    setRecords(prev => prev.map(c =>
      normAddr(c.address) === normAddr(address) && !c.ed25519Pub
        ? { ...c, ...facts, pinSeq: 1, pinnedAt: Date.now() }
        : c,
    ));
  }, []);

  const removeContact = useCallback(async (address: string) => {
    if (!storeRef.current) return;
    await storeRef.current.delete(address);
    // Drop the local pin with the contact: deleting and re-adding is the documented way
    // to accept a legitimate rotation, and a pin left behind would keep rejecting the
    // new key after the user did exactly what they were told to do.
    if (ownerRef.current) await deletePin(ownerRef.current, address);
    setRecords(prev => prev.filter(c => normAddr(c.address) !== normAddr(address)));
    setPinAlerts(prev => prev.filter(a => normAddr(a.address) !== normAddr(address)));
  }, []);

  const value: ContactsContextValue = { contacts, ready, contactByAddress, nameFor, addContact, updateContact, allowlist, pinKey, removeContact, pinAlerts };
  return createElement(ContactsContext.Provider, { value }, children);
}

export function useContacts(): ContactsContextValue {
  const ctx = useContext(ContactsContext);
  if (!ctx) throw new Error('useContacts must be used within ContactsProvider');
  return ctx;
}
