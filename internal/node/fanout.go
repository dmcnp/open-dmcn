package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/dmcnpb"
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
	// fleet relay-descriptor op — the DHT-free discovery path for onion route selection.
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
// (full replication — the DHT-write replacement). It stores locally first if this node serves
// records, then PutRecords to each peer. Returns the number of nodes (incl. self) that accepted.
// Best-effort: unreachable/rejecting nodes are logged and skipped; an all-fail is an error.
func (n *Node) FanOutRecord(ctx context.Context, kind dmcnpb.RecordKind, record []byte) (int, error) {
	accepted := 0
	if n.records != nil {
		if err := n.records.PutMarshaled(ctx, kind, record); err != nil {
			n.log.Warnf("fanout: local store failed: %v", err)
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
