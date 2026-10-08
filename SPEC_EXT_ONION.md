# DMCNP extension: onion routing

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md).

A core STORE goes straight from the sender to the recipient's relay, so that relay learns which
peer handed it the message. Onion routing sends the message through several relays instead, each
of which learns only the hop before it and the hop after it. The recipient's relay still
verifies the sender's signature on the envelope as it would for a direct STORE. It no longer
sees the network location the message came from.

Who needs it: senders that want to hide who writes to whom, relays that agree to carry onion
traffic, and anyone writing to a mailbox or domain that requires it (§4).

## 1. Building a route

A sender builds a multi-hop route ending at the recipient's home relay:

- **Hop keys** come from each relay's `RelayDescriptor` (`SPEC_CORE.md` §6). A sender MUST
  verify the descriptor and check that its credential carries the `node` role for the domain it
  names, with the peer ID's key as subject, before sealing anything to it.
- **Default 3 hops.** The last hop is the recipient's relay, which performs delivery. The
  earlier hops are chosen at random from candidates with distinct peer IDs, in distinct /24
  networks and distinct domains, so that no two hops share an operator or a network. A sender
  that cannot find enough diverse relays fails rather than quietly building a weaker route. (The
  reference implementation has a relaxed mode that keeps only distinct peers, for small test
  fleets.)
- **Optional guard.** A sender may pin a stable entry hop across sends, so that it does not keep
  drawing new entry relays, any of which could be hostile. Tor uses guards for the same reason.
  Choosing and rotating the guard is the sender's concern.

## 2. Layers

Each layer is an **`OnionPacket`** sealed to one hop's X25519 key with the same KEM/DEM scheme
as the message model: a fresh ephemeral X25519 key per layer, `X25519` with the hop's key,
`HKDF-SHA256`, then `AES-256-GCM` (12-byte nonce, 16-byte tag). `OnionPacket.version` names the
key derivation, and a relay MUST dispatch on it:

| `version` | HKDF `info` |
|---|---|
| 1 | `"dmcn-onion-layer-v1"` |
| 2 | `"dmcn-onion-layer-v2" ‖ eph_pub ‖ relay_pub` |

Generation 2 binds the layer key to the key pair it was derived for, as the message model's
`kdf` generation 2 does (`SPEC_CORE.md` §3).

The plaintext of a layer is an **`OnionLayer`**: `next_hop` (the next relay's peer ID, or the
literal `DELIVER` at the last hop), `ttl_unix` (an absolute expiry), and exactly one of `inner`
(the next hop's packet) or `delivery` (a marshalled `StoreRequest`, at the last hop). Only the
innermost delivery layer is padded, to its own bucket classes.

## 3. Forwarding

**`OnionForward{packet}` → `OnionForwardResponse{accepted}`** on `/dmcn/relay/1.0.0`. The relay
peels one layer with its onion key, drops the packet if it has expired, and then either forwards
`inner` to `next_hop` or, at `DELIVER`, handles `delivery` as an ordinary STORE, with the same
sender signature check and the same mailbox. `accepted` is a hop-by-hop acknowledgement. The
reference relay remembers forwarded packets for 10 minutes, so a retried packet is acknowledged
again without being delivered twice.

`OnionForward` is connection-gated: a relay accepts it only from a credential-admitted peer
(`/dmcn/join`, [`SPEC_EXT_FLEET.md`](SPEC_EXT_FLEET.md)). The entry hop is therefore reached
from the sender's own relay or from a client holding a `client` credential.

Errors:

| Code | Meaning |
|---|---|
| `ONION_DISABLED` | this relay does not carry onion traffic |
| `ONION_PEEL` | the layer does not open with this relay's key |
| `ONION_EXPIRED` | `ttl_unix` has passed |
| `ONION_FORWARD` | no inner packet, an invalid next hop, or the next hop is unreachable |
| `ONION_DELIVER` | the delivery payload is empty or malformed |
| `ONION_REQUIRED` | (on a direct STORE) the recipient requires onion delivery |
| `UNAUTHORIZED` | the caller is not a credential-admitted peer |

## 4. Requiring onion delivery

A mailbox can require onion delivery (`IdentityRecord.require_onion`, covered by the owner
self-signature), and so can a whole domain (`REQUIRE_ONION`, DAR `policy_flags` bit 2). The
effective policy is either one. A relay then refuses a direct STORE to that recipient with
`ONION_REQUIRED`. The reference relay learns a mailbox's policy when the mailbox is fetched,
from the identity record and the domain's DAR, so the binding of key to policy comes from signed
records rather than from whoever is asking.

This is the one place an extension adds an interop requirement (`SPEC_CORE.md` §7). A sender
that implements only the core cannot write to such a mailbox. A domain that sets `REQUIRE_ONION`
is choosing to be reachable only by onion-capable senders, and should say so to the people it
expects to hear from.
