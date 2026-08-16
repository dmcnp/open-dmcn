package identity

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// FleetNode is one node/relay in a fleet roster: its peer ID, dial addresses, and
// (informationally) the roles it serves. The node still proves its own membership
// Credential at /dmcn/join — the roster only advertises where to find it.
type FleetNode struct {
	PeerID     string
	Multiaddrs []string
	Roles      []string
}

// FleetRoster is the fleet owner's root-signed, monotonic-revision list of the nodes that
// serve the fleet, anchored to the fleet domain's DNS fingerprint (its own DAR root key).
// It is the availability/discovery layer that replaces the DHT's provider records: a reader
// bootstraps from a few DNS "seed=" endpoints, fetches this roster from any of them, and
// learns the full authoritative node set (so discovery is not single-pinned).
//
// The roster's signature only vouches for "these nodes serve this fleet" — identity records
// and DARs remain trust-anchored to each mailbox domain, so a lying roster is an availability
// concern, never a forgery vector.
type FleetRoster struct {
	Version       uint32
	FleetDomain   string
	Nodes         []FleetNode
	Revision      uint64
	CreatedAt     time.Time
	SelfSignature [64]byte
}

// NewFleetRoster builds an unsigned, empty roster for a fleet domain created at `at`.
// Revision starts at 1.
func NewFleetRoster(fleetDomain string, at time.Time) (*FleetRoster, error) {
	if err := validateDomain(fleetDomain); err != nil {
		return nil, err
	}
	return &FleetRoster{Version: 1, FleetDomain: fleetDomain, Revision: 1, CreatedAt: at.UTC()}, nil
}

func (r *FleetRoster) signableBytes() ([]byte, error) {
	pb := r.ToProto()
	pb.SelfSignature = nil
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("protobuf marshal: %w", err)
	}
	return data, nil
}

// Sign sets SelfSignature using the fleet domain's current root private key.
func (r *FleetRoster) Sign(root *IdentityKeyPair) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: fleet roster sign: %w", err)
	}
	sig, err := signCtx(root.Ed25519Private, ctxFleetRoster, data)
	if err != nil {
		return fmt.Errorf("identity: fleet roster sign: %w", err)
	}
	copy(r.SelfSignature[:], sig)
	return nil
}

// Verify checks the self-signature against the supplied fleet-domain root public key (the
// caller selects the root key effective when the roster was signed, via the fleet DAR).
func (r *FleetRoster) Verify(rootPub ed25519.PublicKey) error {
	data, err := r.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: fleet roster verify: %w", err)
	}
	if err := verifyCtx(rootPub, ctxFleetRoster, data, r.SelfSignature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// ToProto converts the roster to its protobuf representation.
func (r *FleetRoster) ToProto() *dmcnpb.FleetRoster {
	pb := &dmcnpb.FleetRoster{
		Version:       r.Version,
		FleetDomain:   r.FleetDomain,
		Revision:      r.Revision,
		CreatedAt:     r.CreatedAt.Unix(),
		SelfSignature: r.SelfSignature[:],
	}
	for _, n := range r.Nodes {
		pb.Nodes = append(pb.Nodes, &dmcnpb.FleetNode{
			PeerId:     n.PeerID,
			Multiaddrs: n.Multiaddrs,
			Roles:      n.Roles,
		})
	}
	return pb
}

// FleetRosterFromProto builds a roster from protobuf.
func FleetRosterFromProto(pb *dmcnpb.FleetRoster) (*FleetRoster, error) {
	if pb == nil {
		return nil, fmt.Errorf("identity: nil fleet roster protobuf")
	}
	r := &FleetRoster{
		Version:     pb.Version,
		FleetDomain: pb.FleetDomain,
		Revision:    pb.Revision,
		CreatedAt:   time.Unix(pb.CreatedAt, 0).UTC(),
	}
	copy(r.SelfSignature[:], pb.SelfSignature)
	for _, n := range pb.Nodes {
		r.Nodes = append(r.Nodes, FleetNode{
			PeerID:     n.PeerId,
			Multiaddrs: append([]string(nil), n.Multiaddrs...),
			Roles:      append([]string(nil), n.Roles...),
		})
	}
	return r, nil
}

// FleetRosterFromProtoBytes deserializes a roster from raw protobuf bytes.
func FleetRosterFromProtoBytes(data []byte) (*FleetRoster, error) {
	pb := &dmcnpb.FleetRoster{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: fleet roster unmarshal: %w", err)
	}
	return FleetRosterFromProto(pb)
}
