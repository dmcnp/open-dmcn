# The DMCN Protocol (DMCNP) — Core

DMCN (the Decentralized Mesh Communication Network) is a peer-to-peer,
end-to-end-encrypted store-and-forward mail network where **cryptographic identity
replaces SMTP-style trust**; the DMCN Protocol (DMCNP), specified here, is what its
participants speak:
every address is an Ed25519+X25519 keypair whose self-certifying record is served by the
address's own domain fleet and discovered via DNS ("MX for identity" — no global DHT), and
mail is hybrid-encrypted client-side and parked in recipient-designated relays' mailboxes.

This document describes the **core protocol** — what an independent implementation needs to
interoperate: resolve, verify, send, receive. It is a snapshot of the reference
implementation, not a frozen specification; where they disagree, the implementation and the
schemas in `proto/` are authoritative. Operator/product surfaces (fleet administration,
hosting permits, provisioning, entitlements, relay-assisted client conveniences) are
**extensions outside this core** — see §8 for how they attach without touching it.

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
 relay service        /dmcn/relay/1.0.0 — STORE / FETCH / mailbox / onion / resolve
        │
 trust / federation   Credential PKI (DNS-anchored DAR), /dmcn/join handshake
        │
 transport            libp2p streams (no DHT — discovery is DNS-seeded)
```

## 1. Identity & addressing

- An identity is an **Ed25519 signing key + X25519 key-exchange key**; the address is
  `local@domain`.
- It is a self-signed **`IdentityRecord`** carrying a monotonic owner-signed `revision`. The
  owner self-signature covers the *identity core* (address, keys, created/expires,
  verification tier, onion flag, revision) — **but not `RelayHints`** (routing is
  operator-owned; see §4) and not the embedded operator credentials.
- **Resolution is DNS-seeded, per-domain — there is no global directory.** A resolver reads
  the mailbox domain's `_dmcn.<domain>` DNS TXT record:

  ```
  _dmcn.<domain>  TXT  "dmcn-verification=v1; fp=<40-hex>[; fleet=<domain>][; seed=<multiaddr>]..."
  ```

  `fp=` is the trust anchor — the first 20 bytes of `SHA-256(ed25519_pub ‖ x25519_pub)` of
  the domain's root key, uppercase hex. `fleet=` optionally defers hosting to another
  domain's nodes (discovery only — spoofing it is DoS, never forgery). `seed=` lists
  bootstrap multiaddrs, each ending `/p2p/<peerID>` so the transport handshake
  authenticates the endpoint. The resolver dials a seed, fetches the domain's DAR and the
  `IdentityRecord` (plus removal/blocklist companions), and verifies everything against the
  mailbox `fp=`. Records are self-certifying, so a wrong or hostile fleet is **DoS-only,
  never a forgery vector**; a domain is served only by its own fleet, never a global
  overlay a foreign majority could censor. NXDOMAIN / no `_dmcn` record means the address
  does not exist; transient DNS failure fails closed.
- **Verification tiers:** addresses register at `TierUnverified` (valid but untrusted) and
  are raised to `TierDomainDNS` by a domain attestation. Verification is enforced
  *reader-side*, so unverified addresses still exist and function; trust is an upgrade,
  not a gate at registration.

## 2. Trust: the Credential PKI

Trust is **domain-anchored, not per-message**. Each domain has a **DomainAuthorityRecord
(DAR)**, served by the domain's fleet and anchored by its `_dmcn` DNS record. The root
delegates to **issuers** (carried in the DAR) under a monotone grants calculus — an issuer
cannot delegate more than it holds, scope only narrows, and grant-bearing credentials
require the `grant` capability to be issued.

A **`Credential`** binds a subject key to a domain along two independent axes: **roles**
(what the credential *is*) and **grants** (actions it *may perform*).

Core roles: `authority` / `sub-authority` (domain authority keys), `node` (a relay's
libp2p peer key — federating), `bridge` (an SMTP bridge peer key), `client` (a pure-client
peer key), `address` (the domain's attestation of an address↔key binding), `routing` (the
operator-owned `RelayHints` for an address). Core grants: `routing`, `address`, `grant`
(delegate). Further roles/grants exist as operator extensions (§8).

**Issuance is authorized by grants, not by a role**: any DAR-enrolled credential whose
grants cover a leaf's roles may issue it; an issued credential is not valid until signed.
Credentials verify by **chaining to the DNS-anchored root** (max depth 8), with a
root-signed **`CredentialBlockList`** companion record for timestamped / key-compromise
revocation. The `address` and `routing` credentials are embedded *inside* the
`IdentityRecord` and excluded from the owner self-signature — so the operator can
(re)issue them (e.g. to re-point routing) without the mailbox owner's key.

**Signing convention (every signature in the protocol):**

```
sig = Ed25519(priv, ctx ‖ deterministic_protobuf(message_without_signature))
```

The canonical form is deterministic protobuf serialization (stable map ordering) of the
message with its signature field cleared; `ctx` is a per-type NUL-terminated
domain-separation tag (e.g. `dmcn-identity-self-v1\0`, `dmcn-dar-self-v1\0`,
`dmcn-credential-v1\0`). One deliberate exception: the whole-message `SignedMessage`
signature is computed over the canonical plaintext with no context tag.

## 3. The message model (client-side, three layers)

`PlaintextMessage` → `SignedMessage` (Ed25519 sender signature) → **`EncryptedEnvelope`**:

- one per-message **AES-256-GCM content key (CEK)**, wrapped per recipient device:

  ```
  cek = random 32 bytes
  for each recipient device:
      eph         = fresh X25519 keypair
      shared      = X25519(eph_priv, recipient_pub)
      kwk         = HKDF-SHA256(shared, info="dmcn-cek-wrap-v1")
      wrapped_cek = AES-256-GCM(kwk, cek)          # nonce 12, tag 16
  ```

- sealed blobs are **padded to size-class buckets** (1 KB / 4 KB / 16 KB / 64 KB / 256 KB /
  1 MB, then round-up-to-MB; layout `[4-byte BE length][payload][zero padding]`) for
  traffic-analysis resistance;
- envelope v2 is **split** into a small listable encrypted header (sender, subject,
  snippet, recipient lists, body commitments) and a large body, so listing an inbox never
  reads bodies; the bcc list appears only on the sender's own copy;
- the header's **`snippet`** is the **leading text of the body**, not a free-form summary:
  the longest valid-UTF-8 prefix of the body's first 140 bytes, empty for a non-text body.
  Producers MUST derive it from the body they are sealing. It is covered by the header
  signature, but nothing in the envelope *binds* it to the body the way `body_hash` and the
  body content address do — so a signer can emit a header whose snippet disagrees with its
  own body, and a reader that never fetches the body cannot tell. Readers SHOULD therefore
  re-derive it once the body is decrypted and surface a mismatch: both halves are signed by
  the same key, so a disagreement is a deliberate act by the signer, not corruption. Because
  it IS body text, a reader that withholds an untrusted sender's body should withhold the
  snippet on the same terms — it is a fragment of the thing being withheld;
- the header may carry a **`sender_display`** name — the human-readable name legacy mail
  puts in its From header, which a bridge would otherwise have to discard. It is covered by
  the header signature, so no relay can rewrite it, but it is **asserted, not verified**:
  whoever signed the header chose it. Readers MUST render it only alongside
  `sender_address`, never in place of it, and MUST NOT key trust, allowlist, or blocklist
  decisions on it. Producers should sanitize it (single line, no control or bidirectional
  formatting codepoints) before signing, and should emit one only where a name was
  genuinely supplied — a self-asserted name on a cryptographically identified sender is a
  spoofing surface that buys nothing;
- the body ciphertext blob (`body_nonce‖encrypted_body‖body_tag`) is **content-addressed**
  (`CIDv1(raw, sha2-256)` = `0x01 0x55 0x12 0x20 ‖ SHA-256(blob)`): carried in the clear
  on the envelope for keyless relay verification and committed inside the **signed**
  header. Distinct from the whole-envelope SHA-256 used for retry idempotency.
- `ratchet_pub_key` is reserved for a double-ratchet forward-secrecy upgrade and is zero
  in v1.

All cryptography is **client-side**; relays only ever handle sealed envelopes.

## 4. Routing

- A recipient's mailbox lives on the relays named in its **`RelayHints`** (an ordered
  list: primary + fallbacks).
- **`RelayHints` is operator-owned**: carried in the `routing` credential (signed by a
  `routing`-granted issuer), not the owner self-signature — so an operator can re-point it
  without the mailbox owner's key.
- **Send** = look up the recipient's record → STORE to the first reachable hint
  (failover), or to **all** reachable hints when the recipient's domain DAR sets
  `PolicyReplicateMailbox`. **Receive** = FETCH from *all* your hints and dedup.
- **Portability** = republish with new hints; the address never changes.
- *How* an operator chooses and maintains hints (placement, reservation, rebalance,
  drain) is operator behavior outside the core; the core defines only the hints' format,
  ownership, and how senders/receivers use them.

## 5. Wire protocols (libp2p)

| protocol | framing | purpose |
|---|---|---|
| `/dmcn/relay/1.0.0` | 4-byte big-endian length prefix + protobuf (4 MB frame cap; bodies chunked past it) | `Store` / chunked `StoreInit`, `FetchInit` → `FetchChallenge` → signed-nonce proof, mailbox ops (`List`/`Body`/`Delete`), the resolve ops (`GetIdentity`/`GetDAR`/`GetFleetRoster`/`GetRemoval`/`GetBlocklist`/`GetRelayDescriptor`) + `PutRecord` (record publication/replication, re-verified on ingest), `Ack`, `Ping`, `OnionForward` |
| `/dmcn/peers/1.0.0` | length-prefixed JSON | cluster peer discovery |
| `/dmcn/join/1.0.0` | varint-delimited protobuf | mutual credential handshake — each side presents its `Credential` + DAR; verified peers enter the set that gates federation |

Every core operation authorizes in one of three ways — none of which is a password:
**message-authenticated** ops carry their proof in the message (a store is valid because
the sender signed the envelope; a fetch is valid because the client answers the relay's
32-byte nonce challenge with a signature from the account key);
**connection-gated** ops (`Ack`, `OnionForward`) require a credential-admitted federated
peer; **public reads** return signed records the reader verifies independently — the one
public write, `PutRecord`, self-gates by re-verifying every record on ingest (self-sig,
DNS anchoring for a DAR, monotonic-revision anti-rollback), so an unverifiable record
simply cannot be stored.

**Federation is deny-by-default and credential-gated**: connections stay open so
`/dmcn/join` can run, and the participation gates check the join credential set.

Vacated arm numbers in `RelayRequest`/`RelayResponse`/`MailboxOp` are `reserved` with
gravestone comments — they belonged to operator extensions (§8) and must never be reused.

## 6. Onion routing (optional capability)

Relays may serve a self-anchored **`RelayDescriptor`** (their X25519 onion key + `node`
credential, signed by their libp2p key — recoverable from the peer ID, so it verifies
without trusting the server), fetched via `GetRelayDescriptor`. A sender builds a
multi-hop onion route (default 3 hops; hops in distinct /24 networks and distinct
domains; optional stable guard entry), ending at the recipient's home relay. Each layer
is an `OnionPacket` sealed to one hop's key; only the innermost delivery layer is padded
to its own bucket classes. A mailbox (`require_onion`) or domain (`PolicyRequireOnion`)
can require onion delivery, in which case relays reject direct STOREs with
`ONION_REQUIRED`.

## 6b. Personal storage

A mailbox holder may keep per-account state on their home relay: contacts, sent messages,
read/unread and labels, client settings. Logical keys are `"<namespace>/<id>"` and the relay
treats them as opaque strings; `MailboxKvList` pages a `"<namespace>/"` prefix.

**Values are sealed to the owner alone.** The relay stores ciphertext for which it holds no
key — it can count bytes and serve blobs back, and that is all. This is the same posture as the
mailbox itself, which is why it belongs here rather than in an operator extension: a relay that
already holds someone's sealed mail is not made more trusted by also holding sealed metadata
about it.

Ops ride the same FETCH-authenticated `MailboxOp` stream as `list`/`body`/`delete`
(`MailboxKvGet`, `MailboxKvPut`, `MailboxKvList`, `MailboxKvDelete`, `MailboxKvStat`), so
control of the recipient identity is already proven and every op is scoped to that owner.

A per-key monotonic version supports optional compare-and-swap: `expected_version` non-zero
requires the stored key to be at exactly that version, and a mismatch returns `CONFLICT`. This
is what lets a singleton document edited on two devices resolve rather than silently lose a write.

Storage is **optional for a relay**. One that does not offer it answers `UNSUPPORTED`, and a
client is expected to fall back to keeping the state locally — single-device, but working. A
relay that does offer it applies its own byte cap per account, covering mail and personal storage
together; `MailboxKvStat` reports the figure actually enforced. Per-account entitlements are an
extension concern and are not part of the core (§8).

Without this, every client either stays single-device or invents its own incompatible sync, which
is the outcome an interoperable mail protocol exists to avoid. It is the role IMAP plays alongside
SMTP: the store, and the state that belongs with it.

## 7. SMTP bridge (optional capability)

An implementation may operate an SMTP↔DMCN bridge. A bridge is **infrastructure, not a
correspondent**: it has no DMCN address and no directory entry. It is a peer whose key
carries a `bridge` credential (§5) issued by the domain authority, and that credential is
the whole basis on which anyone believes it.

A bridge maps the legacy sender onto `sender_address` + `sender_display`. The identity it
should carry is the one it authenticated — the **From header**, which is what DMARC
evaluates and what a reader recognizes — not the SMTP envelope sender, which for bulk mail
is a per-message bounce address that makes every message look like a new correspondent. The
envelope sender is preserved in the classification record below.

Inbound legacy mail is authenticated (SPF/DKIM/DMARC) at the bridge, and the verdict
travels as a signed **`BridgeClassificationRecord`** attachment
(`application/x-dmcn-bridge-classification`) inside the sealed envelope. Outbound delivery
returns a signed **`BridgeDeliveryReceipt`**. Both carry the bridge's `bridge` credential,
so a recipient verifies an attestation with no lookup at all:

1. the record's signature is valid for the key it carries;
2. the attached credential is signed by the domain authority root and grants `bridge`; and
3. that credential's subject **is** the key that signed the record.

Step 3 is load-bearing. A credential is public — it travels in every message the bridge
signs — so without binding it to the signer, anyone could attach a real bridge's credential
to their own attestation.

The credential is deliberately **not** covered by `bridge_signature`: it carries its own
issuer signature, the subject-equals-signer check defeats substitution, and the whole record
rides inside the end-to-end-signed message that delivers it. Covering it would mean a
credential could not be re-issued without invalidating every attestation ever made under it.

`bridge_address` is the bridge's libp2p peer ID, and is informational — for display and
logs. It is not an address anyone can send to.

**Discovery (outbound).** A domain advertises its bridge with a `bridge=` token in its
`_dmcn` TXT record — a multiaddr including `/p2p/<peerID>`, the DMCN analogue of an MX
record. A sender resolves the token, fetches that peer's self-anchored `RelayDescriptor`,
and requires it to carry a `bridge` credential whose subject is that peer, before sealing
anything to the descriptor's X25519 key.

The DNS token discovers; the credential decides. That separation matters more here than for
`seed=`: a relay only ever holds sealed envelopes, but a bridge **decrypts** outbound mail in
order to hand it to SMTP, so whoever answers a `bridge=` token reads the plaintext. A domain
that advertises no `bridge=` simply cannot send outside DMCN.

These are message payloads, not wire ops: the bridge speaks the same core relay protocol as
everyone else. Honest edge: mail crossing a bridge is TLS-in-transit on the legacy side, not
end-to-end encrypted — and that TLS is opportunistic, so it is unauthenticated. A bridge
should not verify peer certificates on outbound STARTTLS: SMTP has no trust anchor, so the
practical alternative to unverified TLS is cleartext rather than verified TLS. DANE or
MTA-STS are the mechanisms that make it authenticated; neither is required by this spec.

## 8. Extension points (how everything else attaches)

The core deliberately defines the *attachment surfaces* for extensions rather than the
extensions themselves:

- **`IdentityRecord.operator_credentials` (field 28)** — operator-attached credentials
  beyond routing, semantics identified by each credential's roles/attributes; excluded
  from the owner self-signature like `address_credential`/`routing_credential`. The
  same-revision anti-rollback tiebreak is the newest `issued_at` across
  `routing_credential` and these.
- **`Credential.attributes` under `ext.`-prefixed keys** — signature-covered extension
  payloads (base64-encoded marshaled extension messages) without core schema coupling.
- **Separate libp2p protocol IDs** — extension surfaces run their own protocols beside
  the core (`/dmcn/relay` never carries them). Reserved core numbers mark where earlier
  drafts carried them.
- **DAR `policy_flags`** — core defines bits 0 (`REQUIRE_COUNTERSIGN`), 2
  (`REQUIRE_ONION`) and 3 (`REPLICATE_MAILBOX`); other bits are reserved for extensions.

An implementation that ignores every extension interoperates fully: extensions may add
operator capability, never interop requirements.
