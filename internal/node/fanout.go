package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/registry"
	"dmcn.dev/open-dmcn/internal/relay"
)

// LoadStaticDNS reads a static _dmcn config file — a JSON object mapping domain →
// {fingerprint, fleet, seeds} — for Config.StaticDNS. It supplies the resolver's trust anchor +
// discovery seeds where there is no live DNS (dev cluster, CI) and doubles as a production operator
// seed-pin. An empty path returns (nil, nil).
func LoadStaticDNS(path string) (map[string]domainverify.Record, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("node: read static DNS %s: %w", path, err)
	}
	var m map[string]domainverify.Record
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("node: parse static DNS %s: %w", path, err)
	}
	return m, nil
}

// seedOwnRecords stores the node's own domain DARs (from its join bundles) into its local
// RecordStore, so a serving node can answer GetDAR for the domains it is authoritative for even
// before any operator push arrives. No-op for a pure client (no record store).
func (n *Node) seedOwnRecords(ctx context.Context) {
	if n.records == nil {
		return
	}
	for _, b := range n.joinBundles {
		if b.DAR == nil {
			continue
		}
		if err := n.records.PutDAR(ctx, b.DAR); err != nil {
			n.log.Warnf("seed own DAR %s failed: %v", b.DAR.Domain, err)
		}
	}
	// A serving relay also stores its own signed onion descriptor so peers can fetch it via the
	// fleet relay-descriptor op — the discovery path for onion route selection.
	if desc := n.buildSignedDescriptor(); desc != nil {
		if err := n.records.PutRelayDescriptor(ctx, desc); err != nil {
			n.log.Warnf("seed own relay descriptor failed: %v", err)
		}
	}
}

// PublishIdentity replicates a signed IdentityRecord to the fleet (registration / rotation).
func (n *Node) PublishIdentity(ctx context.Context, rec *identity.IdentityRecord) (int, error) {
	data, err := proto.Marshal(rec.ToProto())
	if err != nil {
		return 0, fmt.Errorf("node: publish identity: %w", err)
	}
	return n.FanOutRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_IDENTITY, data)
}

// PublishDAR replicates a signed DomainAuthorityRecord to the fleet (domain onboarding / rotation).
func (n *Node) PublishDAR(ctx context.Context, dar *identity.DomainAuthorityRecord) (int, error) {
	data, err := proto.Marshal(dar.ToProto())
	if err != nil {
		return 0, fmt.Errorf("node: publish DAR: %w", err)
	}
	return n.FanOutRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_DAR, data)
}

// PublishRemoval replicates a signed AddressRemovalRecord (tombstone) to the fleet.
func (n *Node) PublishRemoval(ctx context.Context, rm *identity.AddressRemovalRecord) (int, error) {
	data, err := proto.Marshal(rm.ToProto())
	if err != nil {
		return 0, fmt.Errorf("node: publish removal: %w", err)
	}
	return n.FanOutRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, data)
}

// PublishBlocklist replicates a signed CredentialBlockList to the fleet (revocation).
func (n *Node) PublishBlocklist(ctx context.Context, bl *identity.CredentialBlockList) (int, error) {
	data, err := proto.Marshal(bl.ToProto())
	if err != nil {
		return 0, fmt.Errorf("node: publish blocklist: %w", err)
	}
	return n.FanOutRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_BLOCKLIST, data)
}

// PublishRoster replicates a signed FleetRoster to the fleet.
func (n *Node) PublishRoster(ctx context.Context, roster *identity.FleetRoster) (int, error) {
	data, err := proto.Marshal(roster.ToProto())
	if err != nil {
		return 0, fmt.Errorf("node: publish roster: %w", err)
	}
	return n.FanOutRecord(ctx, dmcnpb.RecordKind_RECORD_KIND_ROSTER, data)
}

// fleetTargets returns the fleet node multiaddrs to replicate a record to: the configured peers,
// augmented by the roster reported by the first reachable peer via the /dmcn/peers op. Deduped.
// (Full replication to start; the receiving relay is the gossip seam for later epidemic spread.)
func (n *Node) fleetTargets(ctx context.Context) []string {
	known := map[string]bool{}
	var targets []string
	add := func(a string) {
		if a == "" || known[a] {
			return
		}
		known[a] = true
		targets = append(targets, a)
	}
	for _, p := range n.peers {
		add(p)
	}
	// Augment from one reachable peer's roster — enough to learn the full fleet node list.
	for _, p := range append([]string(nil), targets...) {
		info, err := ParseRelayHint(p)
		if err != nil || info.ID == n.host.ID() {
			continue
		}
		if err := n.ConnectPeer(p); err != nil {
			continue
		}
		// Complete the credential join first: a credential-gated peer only serves /dmcn/peers to a
		// peer it has admitted, so querying before the (otherwise async) join finishes gets an EOF.
		n.initiateJoin(info.ID)
		discovered, err := n.relay.ClientPeers(ctx, info.ID)
		if err != nil {
			continue
		}
		for _, dp := range discovered {
			add(dp)
		}
		break
	}
	return targets
}

// FanOutRecord replicates a marshaled record of the given kind to every reachable fleet node
// (full replication). It stores locally first if this node serves
// records, then PutRecords to each peer. Returns the number of nodes (incl. self) that accepted.
// Best-effort: unreachable/rejecting nodes are logged and skipped; an all-fail is an error.
func (n *Node) FanOutRecord(ctx context.Context, kind dmcnpb.RecordKind, record []byte) (int, error) {
	accepted := 0
	if n.records != nil {
		// The local write goes through the SAME acceptance rules as a remote push. PutMarshaled does
		// no verification at all, so a daemon publishing its own record stored and then served it
		// unchecked — bypassing key continuity and anti-rollback. For a single self-hosted node this
		// IS the write path, so leaving it unchecked would make the rebind gate decorative here.
		if ok, reason := n.relay.AcceptRecord(ctx, kind, record); !ok {
			n.log.Warnf("fanout: local store rejected the %v record: %s", kind, reason)
		} else {
			accepted++
		}
	}
	for _, addr := range n.fleetTargets(ctx) {
		info, err := ParseRelayHint(addr)
		if err != nil || info.ID == n.host.ID() {
			continue
		}
		if err := n.host.Connect(ctx, *info); err != nil {
			n.log.Warnf("fanout: connect %s failed: %v", info.ID, err)
			continue
		}
		// Complete the credential join before the grant-gated push: the mutual single-exchange
		// join makes the target record OUR credential, so a fleet-managed target authorizes the
		// PutRecord. initiateJoin is synchronous + idempotent (a no-op if already joined or if we
		// hold no credential to present); without it the push races the async on-connect join and
		// a fleet-managed peer rejects it as ungranted.
		n.initiateJoin(info.ID)
		ok, reason, err := n.relay.ClientPutRecord(ctx, info.ID, kind, record)
		if err != nil {
			n.log.Warnf("fanout: PutRecord to %s failed: %v", info.ID, err)
			continue
		}
		if !ok {
			// A peer that missed the tombstone rejects the record that supersedes it — the
			// expected behaviour of a best-effort fan-out, not a race. Repair it in place.
			if n.repairRebindRejection(ctx, info.ID, kind, record, reason) {
				accepted++
				continue
			}
			n.log.Warnf("fanout: PutRecord to %s rejected: %s", info.ID, reason)
			continue
		}
		accepted++
	}
	if accepted == 0 {
		return 0, fmt.Errorf("node: fanout: no node accepted the %v record", kind)
	}
	return accepted, nil
}

// FetchRemovalUnion builds the authoritative removal record for an address by querying EVERY
// reachable fleet node and unioning the tombstones each one holds.
//
// It exists because the naive "fetch the prior record, append, re-sign" pattern is unsafe in two
// independent ways. First, a record fetched from ONE unverified peer and then re-signed with the
// domain root turns the rotation ceremony into a root-signature ORACLE: a hostile node returns a
// record naming a different address, and the admin mints a genuinely root-signed tombstone for an
// address they never touched — precisely the artifact the rebind gate treats as authoritative.
// Second, removal records are an append-only set enforced by the store, so rebuilding from one
// peer's possibly-stale copy would permanently split a divergent fleet.
//
// Every candidate is therefore verified against the domain's DAR and checked to name THIS address
// before its bindings are merged. Unreachable or unverifiable peers are skipped, never fatal.
func (n *Node) FetchRemovalUnion(ctx context.Context, dar *identity.DomainAuthorityRecord, address string) (*identity.AddressRemovalRecord, error) {
	if dar == nil {
		return nil, fmt.Errorf("node: removal union for %s: no domain authority record", address)
	}
	domain := domainverify.DomainOf(address)
	var candidates []*identity.AddressRemovalRecord
	if n.records != nil {
		if data, _ := n.records.GetRemovalBytes(ctx, address); data != nil {
			if rm, err := identity.AddressRemovalRecordFromProtoBytes(data); err == nil {
				candidates = append(candidates, rm)
			}
		}
	}
	for _, addr := range n.fleetTargets(ctx) {
		info, err := ParseRelayHint(addr)
		if err != nil || info.ID == n.host.ID() {
			continue
		}
		if err := n.ConnectPeer(addr); err != nil {
			continue
		}
		n.initiateJoin(info.ID)
		data, err := n.relay.ClientGetRemoval(ctx, info.ID, address)
		if err != nil || data == nil {
			continue
		}
		if rm, err := identity.AddressRemovalRecordFromProtoBytes(data); err == nil {
			candidates = append(candidates, rm)
		}
	}
	union, ok := mergeRemovalCandidates(dar, domain, address, candidates, n.log)
	if !ok {
		return nil, registry.ErrNotFound
	}
	return union, nil
}

// mergeRemovalCandidates unions the tombstones from every candidate removal record that is a
// root-signed record FOR THIS ADDRESS, and rebuilds a fresh record from the result. Pure, so the
// filtering rules that close the root-signature oracle are directly testable.
//
// Every candidate is verified before merging: a record naming a different address, or one not
// signed by a domain root key, contributes nothing. Without that, a single hostile peer's reply
// would be laundered into a root signature by the caller.
func mergeRemovalCandidates(dar *identity.DomainAuthorityRecord, domain, address string, candidates []*identity.AddressRemovalRecord, log logr.Logger) (*identity.AddressRemovalRecord, bool) {
	merged := map[string]identity.RemovedBinding{}
	var maxRevision uint64
	found := false
	for _, rm := range candidates {
		if rm == nil {
			continue
		}
		if !strings.EqualFold(rm.Address, address) || !strings.EqualFold(rm.Domain, domain) {
			log.Warnf("removal union: discarding a record naming %q while resolving %q", rm.Address, address)
			continue
		}
		if !identity.RemovalIsRootSigned(dar, rm) {
			log.Warnf("removal union: discarding a non-root-signed record for %s", address)
			continue
		}
		found = true
		if rm.Revision > maxRevision {
			maxRevision = rm.Revision
		}
		for _, b := range rm.RemovedBindings {
			k := string(b.Ed25519Public)
			// Keep the EARLIEST removal time for a key: a tombstone takes effect when the root
			// first declared it, not when some replica happened to re-record it.
			if prior, ok := merged[k]; ok && !b.RemovedAt.Before(prior.RemovedAt) {
				continue
			}
			merged[k] = b
		}
	}
	if !found {
		return nil, false
	}
	// Rebuild from scratch — never reuse a fetched object's fields, which is what made the old
	// path an oracle.
	union, err := identity.NewAddressRemovalRecord(domain, address, time.Now().UTC())
	if err != nil {
		return nil, false
	}
	union.Revision = maxRevision
	for _, b := range merged {
		union.RemovedBindings = append(union.RemovedBindings, b)
	}
	// Deterministic order so repeated runs produce identical bytes.
	sort.Slice(union.RemovedBindings, func(i, j int) bool {
		return bytes.Compare(union.RemovedBindings[i].Ed25519Public, union.RemovedBindings[j].Ed25519Public) < 0
	})
	return union, true
}

// repairRebindRejection handles the one rejection a publisher can fix: a peer refused an identity
// record because it does not hold the root-signed tombstone that authorizes the key change. Push
// the tombstone to that peer, then retry the identity ONCE. Never recurses.
//
// The rejection is matched on a reason prefix because PutRecordResponse carries only
// {accepted, reason} — adding a code field would be a core schema change for one call site.
func (n *Node) repairRebindRejection(ctx context.Context, pid peer.ID, kind dmcnpb.RecordKind, record []byte, reason string) bool {
	if kind != dmcnpb.RecordKind_RECORD_KIND_IDENTITY || !strings.HasPrefix(reason, relay.ReasonRebindNeedsRemoval) {
		return false
	}
	rec, err := identity.IdentityRecordFromProtoBytes(record)
	if err != nil {
		return false
	}
	data, err := n.removalBytesFor(ctx, rec.Address)
	if err != nil || data == nil {
		n.log.Warnf("fanout: %s rejected %s pending a tombstone, and none could be found to repair with", pid, rec.Address)
		return false
	}
	if ok, why, err := n.relay.ClientPutRecord(ctx, pid, dmcnpb.RecordKind_RECORD_KIND_REMOVAL, data); err != nil || !ok {
		n.log.Warnf("fanout: pushing the tombstone for %s to %s failed: %v %s", rec.Address, pid, err, why)
		return false
	}
	ok, why, err := n.relay.ClientPutRecord(ctx, pid, kind, record)
	if err != nil || !ok {
		n.log.Warnf("fanout: retry after tombstone repair to %s still rejected: %v %s", pid, err, why)
		return false
	}
	n.log.Infof("fanout: repaired %s on %s by pushing the missing tombstone first", rec.Address, pid)
	return true
}

// removalBytesFor returns the marshaled removal record for an address, local store first then the
// fleet — whatever this publisher can reach.
func (n *Node) removalBytesFor(ctx context.Context, address string) ([]byte, error) {
	if n.records != nil {
		if data, _ := n.records.GetRemovalBytes(ctx, address); data != nil {
			return data, nil
		}
	}
	return n.fleetBytes(ctx, domainverify.DomainOf(address), func(ctx context.Context, pid peer.ID) ([]byte, error) {
		return n.relay.ClientGetRemoval(ctx, pid, address)
	})
}
