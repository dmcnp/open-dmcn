package identity

import (
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
// Domain binding: the node self-asserts the Domain it serves, covered by the
// libp2p self-signature that the peer ID itself anchors. That labels the node but
// proves nothing about membership — Credential does that, and it is what federation
// is decided on. (Schema fields 8-10 once carried a domain-authority countersignature
// over the {Domain, PeerID, X25519Public} binding; it was never implemented, and the
// numbers are gravestoned in identity.proto.)
type RelayDescriptor struct {
	PeerID       string
	X25519Public [32]byte
	Multiaddrs   []string
	CreatedAt    time.Time
	Revision     uint64
	Signature    []byte

	// Domain the node self-asserts it serves (empty ⇒ unbound, self-anchored only).
	Domain string

	// Credential (Credential PKI) is the node's membership credential (role "node"),
	// carried so route selection can verify a relay by credential. Subject == PeerID's key.
	Credential *Credential
}

// SignableBytes is the deterministic serialization the node's identity key signs
// over: everything it self-asserts (peer ID, onion key, addrs, time, revision,
// domain) but NOT the libp2p signature itself, and not the Credential, which the
// issuer signs separately. Exported so the node (signer) and the registry
// (verifier) agree on the bytes.
func (d *RelayDescriptor) SignableBytes() ([]byte, error) {
	pb := &dmcnpb.RelayDescriptor{
		PeerId:          d.PeerID,
		X25519PublicKey: d.X25519Public[:],
		Multiaddrs:      d.Multiaddrs,
		CreatedAt:       d.CreatedAt.Unix(),
		Revision:        d.Revision,
		Domain:          d.Domain,
		// Signature intentionally omitted — this is what we sign over.
	}
	data, err := protoMarshal(pb)
	if err != nil {
		return nil, fmt.Errorf("relay descriptor: marshal: %w", err)
	}
	return data, nil
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
