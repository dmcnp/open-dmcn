package identity

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// CredentialBlock is one timestamped, root-signed revocation entry for a key. A block
// is forward-only by default (a retired/rotated key keeps its valid history); a
// compromised key has ALL of its signatures invalidated (its self-asserted IssuedAt
// can't be trusted). See the Credential PKI plan, Revocation.
type CredentialBlock struct {
	Pubkey           ed25519.PublicKey
	EffectiveFrom    time.Time // creds with IssuedAt >= this are rejected
	Compromised      bool      // true ⇒ invalidate ALL of the key's signatures
	CompromisedSince time.Time // optional best-effort earlier cutoff (compromised only)
	CreatedAt        time.Time
}

// CredentialBlockList is a domain's root-signed blocklist (a separate DHT record so the
// DAR doesn't churn on every block).
type CredentialBlockList struct {
	Domain    string
	Blocks    []CredentialBlock
	Revision  uint64
	Signature [64]byte
}

// Blocked reports whether a credential signed by `pub` with the given IssuedAt is
// revoked. A nil list blocks nothing.
func (l *CredentialBlockList) Blocked(pub ed25519.PublicKey, issuedAt time.Time) bool {
	if l == nil || len(pub) == 0 {
		return false
	}
	for i := range l.Blocks {
		b := &l.Blocks[i]
		if !bytes.Equal(b.Pubkey, pub) {
			continue
		}
		if b.Compromised {
			// Stolen key: its IssuedAt can't be trusted. Default = invalidate everything;
			// an explicit CompromisedSince narrows it (best-effort).
			if b.CompromisedSince.IsZero() {
				return true
			}
			return !issuedAt.Before(b.CompromisedSince)
		}
		// Retired/rotated key: forward-only — pre-block history stays valid.
		return !issuedAt.Before(b.EffectiveFrom)
	}
	return false
}

func (l *CredentialBlockList) signableBytes() ([]byte, error) {
	pb := l.ToProto()
	pb.Signature = nil
	return protoMarshal(pb)
}

// Sign sets the list signature using the domain root key.
func (l *CredentialBlockList) Sign(root *IdentityKeyPair) error {
	data, err := l.signableBytes()
	if err != nil {
		return err
	}
	sig, err := signCtx(root.Ed25519Private, ctxKeyCompromise, data)
	if err != nil {
		return err
	}
	copy(l.Signature[:], sig)
	return nil
}

// Verify checks the list signature against a domain root key.
func (l *CredentialBlockList) Verify(rootPub ed25519.PublicKey) error {
	data, err := l.signableBytes()
	if err != nil {
		return err
	}
	if err := verifyCtx(rootPub, ctxKeyCompromise, data, l.Signature[:]); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// ToProto converts the blocklist to protobuf.
func (l *CredentialBlockList) ToProto() *dmcnpb.CredentialBlockList {
	pb := &dmcnpb.CredentialBlockList{
		Domain:    l.Domain,
		Revision:  l.Revision,
		Signature: l.Signature[:],
	}
	for i := range l.Blocks {
		b := &l.Blocks[i]
		eb := &dmcnpb.CredentialBlock{
			Pubkey:        b.Pubkey,
			EffectiveFrom: b.EffectiveFrom.Unix(),
			Compromised:   b.Compromised,
			CreatedAt:     b.CreatedAt.Unix(),
		}
		if !b.CompromisedSince.IsZero() {
			eb.CompromisedSince = b.CompromisedSince.Unix()
		}
		pb.Blocks = append(pb.Blocks, eb)
	}
	return pb
}

// CredentialBlockListFromProto builds a blocklist from protobuf.
func CredentialBlockListFromProto(pb *dmcnpb.CredentialBlockList) *CredentialBlockList {
	if pb == nil {
		return nil
	}
	l := &CredentialBlockList{Domain: pb.Domain, Revision: pb.Revision}
	copy(l.Signature[:], pb.Signature)
	for _, b := range pb.Blocks {
		cb := CredentialBlock{
			Pubkey:        b.Pubkey,
			EffectiveFrom: time.Unix(b.EffectiveFrom, 0).UTC(),
			Compromised:   b.Compromised,
			CreatedAt:     time.Unix(b.CreatedAt, 0).UTC(),
		}
		if b.CompromisedSince != 0 {
			cb.CompromisedSince = time.Unix(b.CompromisedSince, 0).UTC()
		}
		l.Blocks = append(l.Blocks, cb)
	}
	return l
}

// CredentialBlockListFromProtoBytes deserialises a blocklist.
func CredentialBlockListFromProtoBytes(data []byte) (*CredentialBlockList, error) {
	pb := &dmcnpb.CredentialBlockList{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: blocklist unmarshal: %w", err)
	}
	return CredentialBlockListFromProto(pb), nil
}
