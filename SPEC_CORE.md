# The DMCN Protocol (DMCNP): Core

DMCN (the Decentralized Mesh Communication Network) is a peer-to-peer, end-to-end-encrypted
store-and-forward mail network in which cryptographic identity replaces SMTP-style trust. The
DMCN Protocol (DMCNP) is what its participants speak. Every address is an Ed25519+X25519
keypair. Its self-certifying record is served by the address's own domain fleet and discovered
via DNS ("MX for identity", with no global DHT). Mail is hybrid-encrypted on the client and held
in mailboxes on relays the recipient designates.

This document is the **core**: the smallest set of rules that lets two independent
implementations, on two different domains, resolve each other's addresses and exchange a signed
and encrypted message. **An implementation that does everything in this document implements
DMCN.** Everything else is an optional extension in its own document. An implementation that
ignores every extension still interoperates with every other conforming one; §7 says how
extensions attach, and names the one place where that promise is knowingly broken.

It is a snapshot of the reference implementation, not a frozen specification; where they
disagree, the implementation and the schemas in `proto/` are authoritative.

## The documents

| Document | What it covers | Who needs it |
|---|---|---|
| `SPEC_CORE.md` (this one) | identity, resolution, the credential PKI, the message model, routing, the relay wire protocol | every implementation |
| [`SPEC_EXT_FLEET.md`](SPEC_EXT_FLEET.md) | running one domain on several nodes: fleet roster, record replication, the `/dmcn/join` handshake, peer discovery, mailbox replication | operators with more than one node |
| [`SPEC_EXT_ONION.md`](SPEC_EXT_ONION.md) | onion-routed delivery and the domains and mailboxes that require it | senders that want to hide who writes to whom, and the relays that carry them |
| [`SPEC_EXT_BRIDGE.md`](SPEC_EXT_BRIDGE.md) | the SMTP↔DMCN bridge: its credential, its signed verdicts on legacy mail, and how senders find it | domains that exchange mail with ordinary email, and readers that want to verify a bridge's verdict |
| [`SPEC_EXT_STORAGE.md`](SPEC_EXT_STORAGE.md) | personal storage: owner-sealed key-value state on the home relay (contacts, Sent, flags, settings) | clients that sync across devices |
| [`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md) | owner key rotation, device credentials, and the address history record | domains that let account holders re-key without the operator |

Operator and product surfaces (fleet administration, hosting permits, provisioning,
entitlements, relay-assisted client conveniences) are not in any of these documents. They run
beside the protocol on their own libp2p protocols (§7).

## The layered stack

```
 user identity        Ed25519 (sign) + X25519 (ECDH), address = local@domain
        │              self-certifying IdentityRecord, served by the domain's fleet
 resolution           DNS `_dmcn.<domain>` (fp anchor + fleet= + seeds) → fetch signed
        │              records from the domain's fleet over libp2p, verify vs the anchor
 message model        PlaintextMessage → SignedMessage → EncryptedEnvelope
        │              per-message AES-256-GCM CEK, X25519-wrapped per recipient,
        │              split header/body, padded to size-class buckets
 routing              operator-signed RelayHints (which relays hold my mailbox)
        │
 relay service        /dmcn/relay/1.0.0: STORE / FETCH + mailbox ops / resolve
        │
 trust                Credential PKI (DNS-anchored DomainAuthorityRecord)
        │
 transport            libp2p streams (no DHT; discovery is DNS-seeded)
```

## 1. Identity & addressing

- An identity is an Ed25519 signing key plus an X25519 key-exchange key; the address is
  `local@domain`.
- It is a self-signed **`IdentityRecord`** carrying a monotonic owner-signed `revision`. The
  owner self-signature covers the *identity core* (address, keys, created/expires, verification
  tier, onion flag, revision, forward target, and the rotation fields of
  [`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md)). It does not cover `RelayHints`, which the operator owns (§4), or
  the embedded operator credentials.
- **Expiry.** `expires_at` is set by the owner and covered by the owner self-signature, so no
  relay or operator can extend it or remove it. Once it has passed, the record is treated as if
  it did not exist: a node MUST refuse to store it and MUST NOT serve it, and a reader MUST NOT
  verify it. Zero means the record never expires. Long-lived records, such as an ordinary
  account's, leave it at zero, because only the owner's key can renew it and an owner who lost
  their devices would lose the address. It is meant for records made to be temporary, such as
  the short-lived record a new device uses while it pairs. An operator that wants an address to
  lapse sets `not_after` on the credentials it issues (§2) instead. The record survives, and the
  domain's attestation of it ends.
- **Forwarding: `forward_to`.** The owner may name one other address, DMCN or ordinary email,
  that also receives the address's mail. It is covered by the owner self-signature, so no relay or
  operator can set, change or remove it; empty means no forward. It is in the clear: anyone who
  resolves the address can read it. It adds a copy and takes nothing away: while the mailbox is
  open, mail goes to both, and once the recipient's account is closed (a STORE answers
  `RECIPIENT_CLOSED`, §5) the forward copy is the only one delivered.

  A sender writing to an address whose verified record carries `forward_to` MUST also send the
  message to the target, unless the target is already one of the message's recipients or is the
  sender. The sender resolves the target itself, when it sends:

  - A target with a DMCN identity gets its own copy, sealed end-to-end to it like any other
    recipient's. It is built the way a Bcc copy is (§3): `recipient_address` names the target, so
    the reader's audience check passes, and the signed To/Cc are the message's own, so the target
    sees who the mail was written to.
  - Any other target gets the copy as ordinary email through a bridge. That copy is not
    end-to-end encrypted, and the client MUST say so to the sender before sending.

  One hop only: a sender MUST NOT follow the target's own `forward_to`. A target that gains a DMCN
  identity later starts receiving sealed copies without the owner doing anything, because every
  send resolves it again. Nothing can make a sender honour the forward; one that does not still
  delivers to the mailbox while it is open. A reader that predates this field rejects every record
  carrying it (the signature is checked over re-marshaled fields), so an implementation MUST read
  `forward_to` before any record it serves carries one.
- **Resolution is DNS-seeded and per-domain, with no global directory.** A resolver reads the
  mailbox domain's `_dmcn.<domain>` DNS TXT record:

  ```
  _dmcn.<domain>  TXT  "dmcn-verification=v1; fp=<40-hex>[; fleet=<domain>][; seed=<multiaddr>]..."
  ```

  `fp=` is the trust anchor: the first 20 bytes of `SHA-256(ed25519_pub ‖ x25519_pub)` of the
  domain's root key, in uppercase hex. `fleet=` optionally defers hosting to another domain's
  nodes. It is used for discovery only, so spoofing it is DoS, never forgery. `seed=` lists
  bootstrap multiaddrs, each ending `/p2p/<peerID>` so the transport handshake authenticates the
  endpoint. The resolver dials a seed, fetches the domain's `DomainAuthorityRecord` (§2) and the
  `IdentityRecord` (plus removal/blocklist companions), and verifies everything against the
  mailbox `fp=`. Records are self-certifying, so a wrong or hostile fleet can deny service but
  cannot forge anything. A domain is served only by its own fleet, and no global overlay exists
  that a foreign majority could censor. NXDOMAIN / no `_dmcn` record means the address does not
  exist; transient DNS failure fails closed.
- **The signed `fleet_domain`.** A `DomainAuthorityRecord` may declare the fleet its domain
  defers to. When it does, a resolver MUST refuse a DNS `fleet=` that names a different one. One
  that declares none follows the DNS `fleet=` as discovery only. This matters to a client that
  pins `fp=` but re-reads `fleet=` and `seed=`; in plain DNS, whoever can move `fleet=` can move
  `fp=` too.
- **Retiring an address: `AddressRemovalRecord`.** An address is taken out of service by an
  append-only, per-address removal record, keyed on `SHA-256(address)`, listing the
  `(key, removedAt)` bindings it tombstones. A tombstone does two jobs, and they have different
  signers:

  1. **Suppression.** A tombstoned binding stops verifying: readers MUST drop it to
     `TierUnverified`, and a serving node MUST stop serving it and MUST NOT authenticate a FETCH
     against it. This may be signed either by a domain root key or by the address's own key. The
     holder of an address may always stop being reachable at it, without the operator.
  2. **Re-binding.** Allowing a *different* key to take the address over MUST be authorised by a
     root-signed removal that tombstones the incumbent key. That is the operator override, and
     it frees the address for any key. An owner-signed retirement never frees an address.

     On a domain that enables owner rotation, an owner rotation is the one other way to re-bind
     an address. It is specified, with what it costs, in
     [`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md). A core implementation on a domain without
     it accepts only the root-signed path.

  A removal record is bound to the address it names. `Removed()` matches on the key alone, so a
  retirement at one address MUST NOT suppress another address the same key holds. The two
  signers are told apart by which key verifies the signature; no field on the wire distinguishes
  them, and the signed bytes are unchanged.

  **Precedence.** A root-signed record MAY displace an owner-signed one. That is the operator
  override, and it is how a self-retired address can still be rotated or reissued. An
  owner-signed record MUST NOT displace a root-signed one, or a stolen key could overwrite the
  operator's tombstone and block the recovery that rule (2) exists to preserve. The append-only
  rule (the binding set may only grow) and revision monotonicity apply across both.

- **Verification tiers:** addresses register at `TierUnverified` (valid but untrusted) and are
  raised to `TierDomainDNS` by a domain attestation. Verification is enforced *reader-side*, so
  unverified addresses still exist and function; trust is an upgrade, not a gate at
  registration.

## 2. Trust: the Credential PKI

Trust is anchored in the domain, not in each message. Each domain has a
**`DomainAuthorityRecord`**, served by the domain's fleet and anchored by its `_dmcn` DNS
record. The root delegates to issuers (carried in the same record) under a monotone grants
calculus: an issuer cannot delegate more than it holds, scope only narrows, and issuing a
grant-bearing credential requires the `grant` capability.

A **`Credential`** binds a subject key to a domain along two independent axes: **roles** (what
the credential *is*) and **grants** (actions it *may perform*).

Core roles: `authority` / `sub-authority` (domain authority keys), `node` (a relay's libp2p peer
key), `client` (a pure-client peer key), `address` (the domain's attestation of an address↔key
binding), `routing` (the operator-owned `RelayHints` for an address). Core grants: `routing`,
`address`, `grant` (delegate). Two further roles are defined by extensions: `bridge`
([`SPEC_EXT_BRIDGE.md`](SPEC_EXT_BRIDGE.md)) and `device`
([`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md)). Operators may define more (§7).

**Issuance is authorised by grants, not by a role**: any credential enrolled in the domain's
`DomainAuthorityRecord` whose grants cover a leaf's roles may issue it; an issued credential is
not valid until signed. Credentials verify by chaining to the DNS-anchored root (max depth 8).
Revocation is a root-signed **`CredentialBlockList`** companion record, which covers both
timestamped and key-compromise revocation. The `address` and `routing` credentials are embedded
*inside* the `IdentityRecord` and excluded from the owner self-signature, so the operator can
(re)issue them (to re-point routing, for example) without the mailbox owner's key.

**Signing convention (records and credentials):**

```
sig = Ed25519(priv, ctx ‖ deterministic_protobuf(message_without_signature))
```

The canonical form is deterministic protobuf serialisation (stable map ordering) of the message
with its signature field cleared; `ctx` is a per-type NUL-terminated domain-separation tag (e.g.
`dmcn-identity-self-v1\0`, `dmcn-dar-self-v1\0`, `dmcn-credential-v1\0`).

Four signatures do not follow it, and an implementation has to know them:

| Signature | Signed bytes |
|---|---|
| `SignedMessage` (whole message, §3) | the canonical plaintext, no context tag |
| `StoreRequest` / `StoreInit` `sender_signature` (§5) | the 32-byte SHA-256 of the serialised `EncryptedEnvelope`, no context tag |
| FETCH proof (`FetchProof` / `MailboxOp` `signature`, §5) | the relay's 32-byte challenge nonce as sent, no context tag |
| `RelayDescriptor` `signature` (§6) | deterministic protobuf of the descriptor without its signature and credential, by the node's libp2p key, no context tag |

## 3. The message model (client-side, three layers)

`PlaintextMessage` → `SignedMessage` (Ed25519 sender signature) → **`EncryptedEnvelope`**:

- one per-message **AES-256-GCM content key (CEK)**, wrapped per recipient device:

  ```
  cek = random 32 bytes
  for each recipient device:
      eph         = fresh X25519 keypair
      shared      = X25519(eph_priv, recipient_pub)
      kwk         = HKDF-SHA256(shared, salt="", info=<context>)
      wrapped_cek = AES-256-GCM(kwk, cek)          # nonce 12, tag 16
  ```

  Each wrap states its own derivation generation in `recipient_record.kdf`, and a reader MUST
  dispatch on that value. An absent value (0) means generation 1. That is a protocol rule and
  not a compatibility shim: every wrap written before the field existed used generation 1, and
  stored envelopes are never re-encrypted. Two generations are defined:

  | `kdf` | `info` | header/body additional data |
  |-------|--------|------------------------------|
  | 1 | `"dmcn-cek-wrap-v1"` | none |
  | 2 | `"dmcn-cek-wrap-v2" ‖ eph_pub ‖ recipient_pub` | `"dmcn-aad-hdr-v1\0"` / `"dmcn-aad-body-v1\0"` |

  Generation 2 is the `kem_context = concat(enc, pkRm)` of RFC 9180 §4.1 DHKEM: it binds the
  wrapping key to the pair it was derived for, where generation 1's fixed label binds nothing.
  Both inputs are fixed 32-byte keys, which is what makes the concatenation unambiguous.

  A reader MUST NOT attempt trial decryption, and MUST reject a generation it does not know
  rather than falling back. Reading the one field is enough.

  The field rides the recipient record rather than the envelope because the record is what
  survives storage: a mailbox persists per-recipient entries that drop the envelope's `version`,
  `message_id` and `created_at`. For the same reason the context carries no message identifier
  and no transcript. The identical wrap is also used for sealed blobs that have no message at
  all, where the generation travels as a `kdf` member of the blob's recipient object.

- sealed blobs are **padded to size-class buckets** (1 KB / 4 KB / 16 KB / 64 KB / 256 KB / 1
  MB, then round-up-to-MB; layout `[4-byte BE length][payload][zero padding]`) for
  traffic-analysis resistance;
- envelope v2 is **split** into a small listable encrypted header (sender, subject, snippet,
  recipient lists, body commitments) and a large body, so listing an inbox never reads bodies;
  the bcc list appears only on the sender's own copy. Header and body are sealed under the SAME
  CEK with independent nonces, so each carries an AEAD additional-data label to keep one from
  opening as the other. The labels are selected by the same `kdf` generation the recipient
  record declares, so an envelope's blobs and its wraps can never disagree. Generation 1
  predates the labels and uses none. They are constant for the same reason the wrap context is
  minimal: nothing derived from the envelope survives storage;
- **the key that signs the envelope MUST be the key named in the header's `sender_public_key`.**
  A message carries two signatures with different jobs: one over the whole encrypted envelope,
  presented in the clear when the message is handed to a relay, and one over the header
  plaintext, sealed inside. The outer one lets a relay confirm the party storing a message
  controls the address it named, without learning anything about the contents; the inner one
  tells the recipient who wrote it.

  Requiring one key for both makes those two statements about the same party. It costs nothing,
  since a sender already holds one signing key, and it means a relay's admission check and a
  recipient's authorship check cannot disagree. A relay cannot verify this itself (it holds no
  key for the sealed header), so it is an obligation on producers.

- **a reader MUST bind the claimed sender address to the key that signed.** The header signature
  verifies against `sender_public_key`, a field the signer chose, so on its own it proves only
  that the header is internally consistent. Anyone may name another party's address, name their
  own key, and sign. A reader MUST resolve `sender_address` and compare. Where the directory
  answers and the key differs, the message is not from the address it names: a reader MUST NOT
  render its body, attachments or HTML, and MUST NOT present the claimed address as attribution.
  Where the address does not resolve, the message is reported as unverified but NOT rejected. A
  directory outage, or an ordinary sender bridged in from legacy mail, must not empty a mailbox.

  A relay cannot perform this check. It sees the transport sender that handed it the envelope,
  which is a different, cleartext field, and it holds no key for the sealed header. The two
  answer different questions. The transport sender governs abuse and quota, the header sender
  governs authorship, and only a recipient can establish authorship.

  Without a signed rotation lineage in the directory, a legitimate key change is
  indistinguishable from a forgery, so a reader SHOULD keep rejected messages retrievable rather
  than deleting them.

- **a reader MUST check that the sender addressed the message to the mailbox reading it**: that
  some address in the signed audience (`recipient_address`, `to`, `cc`) resolves to the X25519
  key the envelope was sealed to. A message failing this MUST be surfaced.

  This is the only defence against surreptitious forwarding, and it cannot be replaced by an
  AEAD binding: a legitimate recipient holds the CEK, so it can re-seal the identical header
  plaintext to a third party under any additional data it likes, and the sender's signature
  still verifies, because it covers the header plaintext and not its ciphertext. The audience is
  signed, so that is what a re-target cannot forge.

  The comparison is on the KEY, not the address string. Mailboxes are keyed by X25519 public
  key, so several addresses may share one mailbox; comparing strings would report an account's
  own mail as misaddressed, and repairing that would require consulting an address-grouping
  marker outside this specification. Resolving to a key needs none of that, and an
  implementation unaware of any such grouping applies the rule correctly. An address that does
  not resolve is skipped: a directory miss is not evidence of misaddressing.

  This check rests on the directory, so a fleet willing to bind the original recipient's address
  to the reader's key can defeat it. A bridge is an exception by design: an outbound-to-legacy
  copy names the legacy recipient while being sealed to the bridge's key;
- the header's **`snippet`** is the leading text of the body, not a free-form summary: the
  longest valid-UTF-8 prefix of the body's first 140 bytes, empty for a non-text body. Producers
  MUST derive it from the body they are sealing. It is covered by the header signature, but
  nothing in the envelope *binds* it to the body the way `body_hash` and the body content
  address do. So a signer can emit a header whose snippet disagrees with its own body, and a
  reader that never fetches the body cannot tell. Readers SHOULD re-derive it once the body is
  decrypted and surface a mismatch. Both halves are signed by the same key, so a disagreement is
  a deliberate act by the signer, not corruption. Because it IS body text, a reader that
  withholds an untrusted sender's body should withhold the snippet on the same terms;
- the header may carry a **`sender_display`** name: the human-readable name legacy mail puts in
  its From header, which a bridge would otherwise have to discard. It is covered by the header
  signature, so no relay can rewrite it, but it is **asserted, not verified**: whoever signed
  the header chose it. Readers MUST render it only alongside `sender_address`, never in place of
  it, and MUST NOT key trust, allowlist, or blocklist decisions on it. Producers should sanitise
  it (single line, no control or bidirectional formatting codepoints) before signing, and should
  emit one only where a name was genuinely supplied. A self-asserted name on a cryptographically
  identified sender is a spoofing surface that buys nothing;
- the body ciphertext blob (`body_nonce‖encrypted_body‖body_tag`) is **content-addressed**
  (`CIDv1(raw, sha2-256)` = `0x01 0x55 0x12 0x20 ‖ SHA-256(blob)`): carried in the clear on the
  envelope for keyless relay verification and committed inside the **signed** header. Distinct
  from the whole-envelope SHA-256 used for retry idempotency.
- `ratchet_pub_key` is reserved for a double-ratchet forward-secrecy upgrade and is zero in v1.

All cryptography is **client-side**; relays only ever handle sealed envelopes.

## 4. Routing

- A recipient's mailbox lives on the relays named in its **`RelayHints`** (an ordered list:
  primary + fallbacks).
- **`RelayHints` is operator-owned**: carried in the `routing` credential (signed by a
  `routing`-granted issuer), not the owner self-signature, so an operator can re-point it
  without the mailbox owner's key.
- **A sender MUST check the hints before using them**: they are excluded from the owner
  self-signature, so they count only when backed by a `routing` credential that verifies against
  the recipient domain's `DomainAuthorityRecord`.
- **Send.** Look up the recipient's record and STORE to the first reachable hint, failing over
  to the next. A domain may ask senders to STORE to every reachable hint instead
  (`REPLICATE_MAILBOX`, [`SPEC_EXT_FLEET.md`](SPEC_EXT_FLEET.md)); a core sender that stores to
  the first reachable hint still delivers.
- **Receive.** FETCH from all of your hints and drop duplicates.
- **Portability.** Moving a mailbox means republishing the record with new hints. The address
  never changes.
- How an operator chooses and maintains hints (placement, reservation, rebalance, drain) is
  operator behaviour outside the core. The core defines only the hints' format, ownership, and
  how senders and receivers use them.

## 5. The relay wire protocol

Core traffic runs on one libp2p protocol, **`/dmcn/relay/1.0.0`**.

**Framing.** Every frame is a 4-byte big-endian length followed by that many bytes of protobuf.
A frame is at most 4 MB. A client opens a stream, writes one `RelayRequest`, and reads one
`RelayResponse`; the relay closes the stream after answering. Two operations, chunked STORE and
FETCH, run longer on the same stream.

`RelayRequest` and `RelayResponse` are each a `oneof`: the arm set says which operation a frame
carries, and `ErrorResponse` can answer any request. Vacated arm numbers are `reserved` with
gravestone comments, and must never be reused.

### Core operations

| Request | Response | Authorised by |
|---|---|---|
| `Store` | `StoreResponse` | the sender's signature over the envelope (message-authenticated) |
| `StoreInit` + body chunks | `StoreResponse` | the same, for envelopes too large for one frame |
| `FetchInit`, then `MailboxOp` | `FetchChallenge`, then the op's response | a signature over the relay's nonce by the account key |
| `GetIdentity` | `GetIdentityResponse` | nothing: a public read of a self-authenticating record |
| `GetDAR` | `GetDARResponse` | public read |
| `GetRemoval` | `GetRemovalResponse` | public read |
| `GetBlocklist` | `GetBlocklistResponse` | public read |
| `GetRelayDescriptor` | `GetRelayDescriptorResponse` | public read (§6) |
| `Ping` | `PingResponse` | nothing |

None of these needs a password or a session. A store carries its own proof, the sender's
signature over the envelope. A fetch is proven by answering the relay's challenge with the
account key. A public read returns a signed record that the reader verifies itself, so the
serving node is untrusted transport. A relay MAY throttle request volume from peers it has no
credential for.

The remaining arms of `RelayRequest` belong to extensions (`OnionForward`, `GetFleetRoster`,
`PutRecord`, `GetHistory`, the `MailboxKv*` ops) or to the legacy appendix (`FetchProof`,
`Ack`). A relay that does not implement one answers `INVALID_REQUEST` or `UNSUPPORTED`.

### STORE

`StoreRequest` carries `sender_address`, the `EncryptedEnvelope`, and `sender_signature`:
Ed25519 by the sender's key over the SHA-256 of the serialised envelope (one of the exceptions
in §2). The relay resolves the sender, verifies the signature, checks that the body bytes hash
to the envelope's body content address when it carries one, and files the envelope under the
recipient's X25519 key. It answers with the envelope hash.

**Chunked STORE.** `StoreInit` carries every field of the envelope except the body ciphertext,
plus `body_total_size`. The body then follows as raw frames, each a length-prefixed slice of the
ciphertext, until exactly `body_total_size` bytes have arrived. The reference implementation
sends 1 MB slices. The relay reassembles the envelope, verifies it as above, and answers with
one `StoreResponse`. A relay MAY bound the whole body (the reference implementation refuses more
than 64 MB).

### FETCH and the mailbox operations

1. The client sends `FetchInit{address}`.
2. The relay resolves the address and answers `FetchChallenge{nonce}`, where the nonce is 32
   random bytes.
3. The client sends one `MailboxOp` carrying the nonce, the account key's signature over it, and
   exactly one operation:

   | Op | Response | What it does |
   |---|---|---|
   | `list{limit, cursor}` | `MailboxListResponse{entries, next_cursor}` | a page of `MailboxEntry` rows, newest first: the wrapped content keys and the sealed header, never the body |
   | `body{hash}` | `MailboxBodyHeader`, then the body as raw chunks | the body of one message, chunked as in STORE |
   | `delete{hash}` | `MailboxDeleteResponse` | removes one message |

Each stream carries one operation, so a client that wants a list and then a body runs the
challenge twice. Listing does not consume mail; only `delete` removes it.

`MailboxOp` also has fields for an enrolled device's signature over the same nonce. A relay that
keeps a device registry requires them once a mailbox has enrolled a device; a relay that keeps
none ignores them. The device credential is defined in
[`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md); how devices are enrolled and removed is not part
of the open protocol.

**`REQUIRE_COUNTERSIGN` (`DomainAuthorityRecord` policy bit 0) and reserved local-parts.** On a
domain that sets the bit, an address is not usable until it carries a valid `address` credential
from the domain. The same applies, on any domain, to an address whose local-part is in the
`reserved_local_parts` list of the domain's `DomainAuthorityRecord` (compared
case-insensitively). A relay answers FETCH for such an address with `POLICY_PENDING`, still
accepts mail addressed to it, and releases that mail once the address is countersigned. A relay
refuses STORE from a sender that is not usable under its own domain's policy
(`SENDER_NOT_VOUCHED`). The reference implementation makes one exception: a pending sender may
write to its own domain's countersign inbox, which is how it asks for the credential.

### Ping

`PingResponse` carries a build `version`, uptime, and `capabilities`: lowercase, hyphenated
tokens naming the optional features this build implements. A caller ignores tokens it does not
know and treats an absent token as unsupported. Ping is unsigned diagnostic data.

### Error codes

An error is an `ErrorResponse{code, message}`, where `message` is meant for people. A core
implementation can meet these codes:

| Code | Meaning |
|---|---|
| `INVALID_REQUEST` | malformed request, or an arm this relay does not implement |
| `INVALID_ENVELOPE` | the envelope does not parse, or its body does not match its content address |
| `INVALID_SIGNATURE` | the STORE sender signature does not verify |
| `UNREGISTERED_SENDER` | the sender does not resolve |
| `SENDER_NOT_VOUCHED` | the sender is not usable under its domain's policy |
| `LOOKUP_FAILED` | the relay could not resolve the sender or the fetching address |
| `RATE_LIMITED` | too many STOREs from this sender |
| `MAILBOX_FULL` | the recipient's mailbox is at its cap |
| `NODE_DRAINING` | this node is not accepting new mail; try the next hint |
| `POLICY_PENDING` | the address is not yet usable under its domain's policy |
| `AUTH_FAILED` | the FETCH proof does not verify |
| `MAILBOX_UNAVAILABLE` | this node holds no mailboxes |
| `NOT_FOUND` | no such message |
| `UNAUTHORIZED` | the operation needs a credential the caller has not presented |
| `UNSUPPORTED` | an optional feature this relay does not offer |
| `STORAGE_FAILED`, `INTERNAL_ERROR` | the relay failed; retry or try the next hint |

Extensions add their own codes (`ONION_*`, `CONFLICT`, `QUOTA_EXCEEDED`). A fleet that closes
accounts answers a STORE that stored nothing because every recipient's account is closed with
`RECIPIENT_CLOSED`; it is the account's answer, so a sender does not retry it on another hint.

## 6. Relay descriptors

A relay may publish a **`RelayDescriptor`**: its peer ID, an X25519 key that others can seal to,
its multiaddrs, the domain it serves, a monotonic `revision`, and its membership `credential`.
It is served by `GetRelayDescriptor{peer_id}`, usually by the node it describes.

The descriptor is **self-anchored**. It is signed by the node's libp2p key, and that key is
recoverable from the peer ID, so a reader verifies it without trusting whoever served it. The
signature covers everything the node asserts about itself; it does not cover the credential,
which its issuer signs separately.

The `domain` field is a label, not proof. What vouches for the node is the credential. A reader
that relies on a descriptor MUST check that:

1. the descriptor's signature verifies against the peer ID's key;
2. the credential chains to the named domain's DNS-anchored root and carries the role the reader
   needs; and
3. the credential's subject is the peer ID's key, so a credential cannot be moved onto another
   node's descriptor.

The core itself does not use descriptors. They are here because two extensions depend on them:
onion routing seals each layer to a hop's descriptor key and checks the hop's `node` credential
([`SPEC_EXT_ONION.md`](SPEC_EXT_ONION.md)), and a sender to legacy mail seals to the bridge's
descriptor key after checking its `bridge` credential
([`SPEC_EXT_BRIDGE.md`](SPEC_EXT_BRIDGE.md)).

## 7. Extension points (how everything else attaches)

The core does not define extensions. It defines the places where they attach:

- **`IdentityRecord.operator_credentials` (field 28).** Credentials an operator attaches beyond
  routing. What each one means is given by its roles and attributes. Like `address_credential`
  and `routing_credential`, they are excluded from the owner self-signature. The same-revision
  anti-rollback tiebreak is the newest `issued_at` across `routing_credential` and these.
- **`Credential.attributes` under `ext.`-prefixed keys.** These carry extension payloads
  (base64-encoded, marshalled extension messages) inside the credential's signature, without
  coupling them to the core schema.
- **Further arms of the core messages.** The protocol's own extensions add arms to
  `RelayRequest`, `RelayResponse` and `MailboxOp`, and a relay that does not implement one
  answers `INVALID_REQUEST` or `UNSUPPORTED`. Operator and product surfaces never do this.
- **Separate libp2p protocol IDs.** Operator and product surfaces run their own protocols beside
  the core (`/dmcn/relay` never carries them). Reserved core numbers mark where earlier drafts
  carried them.
- **`DomainAuthorityRecord.policy_flags`.** All the documents share one bit field:

  | Bit | Flag | Defined in |
  |---|---|---|
  | 0 | `REQUIRE_COUNTERSIGN` | this document, §5 |
  | 1 | reserved for operator extensions | |
  | 2 | `REQUIRE_ONION` | [`SPEC_EXT_ONION.md`](SPEC_EXT_ONION.md) |
  | 3 | `REPLICATE_MAILBOX` | [`SPEC_EXT_FLEET.md`](SPEC_EXT_FLEET.md) |
  | 4 | reserved for operator extensions | |
  | 5 | `ALLOW_KEY_ROTATION` | [`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md) |
  | 6 and up | reserved | |

An implementation that ignores every extension interoperates fully: extensions may add
capability, never interop requirements. There is one exception, by design. A mailbox or domain
that requires onion delivery refuses direct STOREs, so a sender that implements only the core
cannot write to it. A domain that sets `REQUIRE_ONION` is choosing to be reachable only by
onion-capable senders ([`SPEC_EXT_ONION.md`](SPEC_EXT_ONION.md)).

## Appendix A. Legacy paths (not required)

These are in the schema, and the reference relay still answers them. No production client uses
them, and a new implementation need not implement them.

- **The drain FETCH: `FetchProof` → `FetchResponse`, then `Ack`.** This was the original receive
  path. After the challenge, the client sent `FetchProof` instead of a `MailboxOp` and received
  every pending envelope in one response, then acknowledged each by hash with `Ack`. It drains a
  transient store that is only filled by non-split envelopes (below). Production reads go
  through `MailboxOp` (§5). `Ack` is answered only for credential-admitted federated peers.
- **The non-split envelope** (`EncryptedEnvelope.encrypted_payload` and `payload_size_class`):
  the whole message sealed as one blob. Producers SHOULD emit the split header/body form of §3,
  and a reader MAY accept a non-split envelope. The reference bridge still accepts one for
  outbound legacy mail, since it decrypts the message at once and never stores it.

## Appendix B. Schema without a specification

The core schema carries a few messages that no implementation writes or reads. They are
placeholders, described here so nobody mistakes them for live protocol:

- **`KeyCompromiseRecord`, `CompromisedKey`.** These were an earlier revocation design.
  Revocation is `CredentialBlockList` (§2). The blocklist still signs under the context tag
  `dmcn-key-compromise-v1\0`, named after the record it replaced; renaming it would invalidate
  every existing blocklist.
- **`AttestationRecord`, `AttestationType`, `IdentityRecord.attestations`.** A record for
  third-party attestations of an identity, designed but never built. A reader ignores the field.
