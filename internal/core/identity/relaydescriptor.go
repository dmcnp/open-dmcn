package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// RelayDescriptor advertises a relay node's onion-routing X25519 key, bound to
// its peer ID and signed by the node's libp2p identity key. The signature is
// produced and verified with libp2p crypto (in the node / registry packages,
// which have the peer-ID machinery) — this package only models the data and the
// deterministic SignableBytes the signature covers.
//
// Domain binding (DMCN PKI): the node self-asserts the Domain it serves (covered
// by the libp2p self-signature), and the domain authority — root or a delegated
// sub-authority — countersigns the stable {Domain, PeerID, X25519Public} binding.
// The countersignature deliberately excludes Multiaddrs/Revision/CreatedAt so it
// survives the frequent liveness re-publish (the node bumps those without needing
// a fresh countersignature). A descriptor with a valid countersignature, whose
// signer is authorized by the domain's DNS-anchored DAR, proves the node belongs
// to the domain — the unit of federation in the domain-anchored model.
type RelayDescriptor struct {
	PeerID       string
	X25519Public [32]byte
	Multiaddrs   []string
	CreatedAt    time.Time
	Revision     uint64
	Signature    []byte

	// Domain binding (optional — empty Domain ⇒ legacy self-anchored-only descriptor).
	Domain                 string
	DomainCountersignature [64]byte
	DomainCountersignedAt  time.Time
	DomainCountersignerPub ed25519.PublicKey

	// Credential (Credential PKI) is the node's membership credential (role "node"),
	// carried so route selection can verify a relay by credential. Subject == PeerID's
	// key. Successor to the domain countersignature above.
	Credential *Credential
}

// SignableBytes is the deterministic serialization the node's identity key signs
// over: everything it self-asserts (peer ID, onion key, addrs, time, revision,
// domain) but NOT the libp2p signature itself nor the domain countersignature
// (which the authority adds afterward). Exported so the node (signer) and the
// registry (verifier) agree on the bytes.
func (d *RelayDescriptor) SignableBytes() ([]byte, error) {
	pb := &dmcnpb.RelayDescriptor{
		PeerId:          d.PeerID,
		X25519PublicKey: d.X25519Public[:],
		Multiaddrs:      d.Multiaddrs,
		CreatedAt:       d.CreatedAt.Unix(),
		Revision:        d.Revision,
		Domain:          d.Domain,
		// Signature + domain-countersig fields intentionally omitted.
	}
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("relay descriptor: marshal: %w", err)
	}
	return data, nil
}

// HasDomainCountersignature reports whether a (legacy) domain countersignature is present.
func (d *RelayDescriptor) HasDomainCountersignature() bool {
	return d.Domain != "" && d.DomainCountersignature != [64]byte{}
}

// ToProto converts the descriptor to its protobuf representation.
func (d *RelayDescriptor) ToProto() *dmcnpb.RelayDescriptor {
	pb := &dmcnpb.RelayDescriptor{
		PeerId:          d.PeerID,
		X25519PublicKey: d.X25519Public[:],
		Multiaddrs:      d.Multiaddrs,
		CreatedAt:       d.CreatedAt.Unix(),
		Revision:        d.Revision,
		Signature:       d.Signature,
		Domain:          d.Domain,
	}
	if d.HasDomainCountersignature() {
		pb.DomainCountersignature = d.DomainCountersignature[:]
		pb.DomainCountersignedAt = d.DomainCountersignedAt.Unix()
		pb.DomainCountersignerPubkey = d.DomainCountersignerPub
	}
	if d.Credential != nil {
		pb.Credential = d.Credential.ToProto()
	}
	return pb
}

// RelayDescriptorFromProto builds a descriptor from protobuf.
func RelayDescriptorFromProto(pb *dmcnpb.RelayDescriptor) (*RelayDescriptor, error) {
	if pb == nil {
		return nil, errors.New("identity: nil relay descriptor protobuf")
	}
	d := &RelayDescriptor{
		PeerID:     pb.PeerId,
		Multiaddrs: pb.Multiaddrs,
		CreatedAt:  time.Unix(pb.CreatedAt, 0).UTC(),
		Revision:   pb.Revision,
		Signature:  pb.Signature,
		Domain:     pb.Domain,
	}
	copy(d.X25519Public[:], pb.X25519PublicKey)
	if len(pb.DomainCountersignature) == 64 {
		copy(d.DomainCountersignature[:], pb.DomainCountersignature)
		d.DomainCountersignedAt = time.Unix(pb.DomainCountersignedAt, 0).UTC()
		d.DomainCountersignerPub = ed25519.PublicKey(pb.DomainCountersignerPubkey)
	}
	if pb.Credential != nil {
		cred, err := CredentialFromProto(pb.Credential)
		if err != nil {
			return nil, fmt.Errorf("identity: relay descriptor credential: %w", err)
		}
		d.Credential = cred
	}
	return d, nil
}

// RelayDescriptorFromProtoBytes deserializes a descriptor from bytes.
func RelayDescriptorFromProtoBytes(data []byte) (*RelayDescriptor, error) {
	pb := &dmcnpb.RelayDescriptor{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: relay descriptor unmarshal: %w", err)
	}
	return RelayDescriptorFromProto(pb)
}
