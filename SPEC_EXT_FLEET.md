# DMCNP extension: fleets

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md).

The core needs only one node per domain: it serves the domain's records and holds its mailboxes,
and anyone can reach it from the `seed=` entries in DNS. This extension is for a domain served
by several nodes, and for nodes that federate with each other. It covers how a reader learns the
whole node set, how records reach every node, how nodes recognise each other, and how a domain
asks senders to keep copies on more than one relay.

Who needs it: operators running more than one node, and relays that take part in
connection-gated operations (`Ack`, and `OnionForward` from
[`SPEC_EXT_ONION.md`](SPEC_EXT_ONION.md)).

## 1. The fleet roster

A **`FleetRoster`** is the fleet owner's signed list of the nodes that serve the fleet: for each
node its peer ID, its multiaddrs and (informationally) the roles it serves. It is signed by the
fleet domain's root key under the context tag `dmcn-fleet-roster-v1\0`, carries a monotonic
`revision`, and is anchored by the fleet domain's own `_dmcn` fingerprint.

A reader bootstraps from a few `seed=` endpoints, fetches the roster from any of them with
`GetFleetRoster{fleet_domain}`, and learns the full set of nodes, so discovery does not depend
on a single pinned seed.

The roster only says *these nodes serve this fleet*. Identity records and DARs stay anchored to
each mailbox domain's own fingerprint, so a lying roster is an availability problem, never a
forgery. A node still proves its own membership with its credential at `/dmcn/join`; the roster
only says where to find it.

## 2. Replicating records

**`PutRecord{kind, record}` → `PutRecordResponse{accepted, reason}`** on `/dmcn/relay/1.0.0`
pushes one self-authenticating record into a node's store. `kind` names the record:

| `RecordKind` | Record |
|---|---|
| `IDENTITY` | `IdentityRecord` |
| `DAR` | `DomainAuthorityRecord` |
| `ROSTER` | `FleetRoster` |
| `REMOVAL` | `AddressRemovalRecord` |
| `BLOCKLIST` | `CredentialBlockList` |
| `HISTORY` | `AddressHistoryRecord` ([`SPEC_EXT_ROTATION.md`](SPEC_EXT_ROTATION.md)) |

The receiving node re-verifies every record before storing it: the self-signature, the DNS
fingerprint anchor for a DAR, and monotonic-revision anti-rollback. A record is stored only if
the node can tell, from state it already trusts, that it legitimately succeeds what it holds, so
a compromised pusher cannot plant a forgery. Identity-record pushes are also gated on the caller
holding the `routing` grant for the record's domain, to keep strangers from filling a node with
valid but unwanted records. The other kinds are root-signed or DNS-anchored, so their signature
is the authority.

## 3. Federation: `/dmcn/join/1.0.0`

Federation is deny-by-default and credential-gated. Connections stay open so the handshake can
run, and what a peer may do afterwards depends on the credential it presented.

`/dmcn/join/1.0.0` is a mutual handshake with varint-delimited protobuf framing. This differs
from the relay protocol's 4-byte frames, and this specification prescribes both. The dialling
side sends a `JoinRequest` and the other side answers with a `JoinResponse`, so both sides
present the same material. Each side presents its `Credential` together with the DAR that
anchors it, so the other can verify it against a direct DNS resolution, even for a foreign
domain at cold start. A peer credentialled in several domains presents one `CredentialBundle`
per domain in `bundles`; the singular `credential` and `dar` fields carry the primary bundle.

A node admits the peer when:

1. the credential's subject is the peer's libp2p key;
2. the credential verifies against the presented DAR, the DAR against the domain's DNS
   fingerprint, and neither is revoked by the domain's `CredentialBlockList`; and
3. for infrastructure roles (`node`, `bridge`), the connection's observed IP matches the
   credential's `ip` or `multiaddr` attribute when one is present. This is defence in depth, not
   the primary check.

An admitted peer is a **credential-admitted** (federated) peer. That status is what the
connection-gated operations require: `Ack` (`SPEC_CORE.md` Appendix A), `OnionForward`, and
`/dmcn/peers` below. A relay MAY also exempt admitted peers from the throttling it applies to
unknown ones. The reference node also admits credentials issued directly by a locally configured
operator key, for its own fleet. That is local configuration and not part of the protocol.

## 4. Peer discovery: `/dmcn/peers/1.0.0`

A node answers `/dmcn/peers/1.0.0` with its list of cluster peer multiaddrs: a 4-byte big-endian
length followed by JSON, `{"peers": ["<multiaddr>", ...]}`. It answers only credential-admitted
peers, so the cluster list is not handed to strangers.

## 5. Mailbox replication: `REPLICATE_MAILBOX`

DAR `policy_flags` bit 3. On a domain that sets it, senders STORE to every reachable relay hint
instead of the first one that answers, so each of the address's relays holds a copy. Receivers
already FETCH from all hints and drop duplicates (`SPEC_CORE.md` §4), so nothing changes on the
receiving side.

A sender that implements only the core stores to the first reachable hint. The message is still
delivered, but only one relay holds it.
