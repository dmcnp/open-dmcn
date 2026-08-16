package relay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	ds "github.com/ipfs/go-datastore"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// Record-store datastore prefixes. These hold the self-authenticating records a fleet node
// serves authoritatively for the domains it hosts.
const (
	recIdentityPrefix   = "/authrec/identity"
	recDARPrefix        = "/authrec/dar"
	recRemovalPrefix    = "/authrec/removal"
	recBlocklistPrefix  = "/authrec/blocklist"
	recRosterPrefix     = "/authrec/roster"
	recDescriptorPrefix = "/authrec/relaydesc" // relay onion descriptor, keyed by peer ID
)

// RecordStore is a fleet node's node-local, authoritative copy of the self-authenticating
// records it serves for the domains it hosts: identity records, DARs, address-removal
// tombstones, credential blocklists, and its fleet roster. It is the DHT-independent source of
// truth behind the fleet-resolution ops.
//
// Unlike AccountStore these records are PUBLIC (any reader may look them up) and
// self-authenticating (signed + DNS-fingerprint-anchored), so they are stored in the clear —
// the store's only job is durable availability that no shared keyspace can censor. A returned
// record is still verified by the reader against the domain's DNS fingerprint; the node serving
// it is untrusted transport.
type RecordStore struct {
	store ds.Batching
}

// NewRecordStore returns a record store over the given (borrowed) datastore.
func NewRecordStore(d ds.Batching) *RecordStore { return &RecordStore{store: d} }

func recKey(prefix, id string) ds.Key {
	h := crypto.SHA256Hash([]byte(id))
	return ds.NewKey(fmt.Sprintf("%s/%s", prefix, hex.EncodeToString(h[:])))
}

func (rs *RecordStore) put(ctx context.Context, prefix, id string, data []byte) error {
	if err := rs.store.Put(ctx, recKey(prefix, id), data); err != nil {
		return fmt.Errorf("recordstore: put %s: %w", prefix, err)
	}
	return nil
}

// get returns the raw bytes for a record, or (nil, nil) when absent.
func (rs *RecordStore) get(ctx context.Context, prefix, id string) ([]byte, error) {
	data, err := rs.store.Get(ctx, recKey(prefix, id))
	if errors.Is(err, ds.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("recordstore: get %s: %w", prefix, err)
	}
	return data, nil
}

// --- Identity records (keyed by address) ---

// PutIdentity stores the signed IdentityRecord for an address.
func (rs *RecordStore) PutIdentity(ctx context.Context, rec *identity.IdentityRecord) error {
	data, err := proto.Marshal(rec.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal identity: %w", err)
	}
	return rs.put(ctx, recIdentityPrefix, rec.Address, data)
}

// GetIdentity returns the signed IdentityRecord for an address, or (nil, nil) when absent.
func (rs *RecordStore) GetIdentity(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	data, err := rs.get(ctx, recIdentityPrefix, address)
	if err != nil || data == nil {
		return nil, err
	}
	return identity.IdentityRecordFromProtoBytes(data)
}

// GetIdentityBytes returns the marshaled IdentityRecord for an address, or (nil, nil) when
// absent — the serve path passes the bytes straight through without a decode round-trip.
func (rs *RecordStore) GetIdentityBytes(ctx context.Context, address string) ([]byte, error) {
	return rs.get(ctx, recIdentityPrefix, address)
}

// --- Domain authority records (keyed by domain) ---

// PutDAR stores the signed DomainAuthorityRecord for a domain.
func (rs *RecordStore) PutDAR(ctx context.Context, dar *identity.DomainAuthorityRecord) error {
	data, err := proto.Marshal(dar.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal dar: %w", err)
	}
	return rs.put(ctx, recDARPrefix, dar.Domain, data)
}

// GetDARBytes returns the marshaled DAR for a domain, or (nil, nil) when absent.
func (rs *RecordStore) GetDARBytes(ctx context.Context, domain string) ([]byte, error) {
	return rs.get(ctx, recDARPrefix, domain)
}

// GetDAR returns the parsed DAR for a domain, or (nil, nil) when absent.
func (rs *RecordStore) GetDAR(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error) {
	data, err := rs.get(ctx, recDARPrefix, domain)
	if err != nil || data == nil {
		return nil, err
	}
	return identity.DomainAuthorityRecordFromProtoBytes(data)
}

// --- Address removal records (keyed by address) ---

// PutRemoval stores the signed AddressRemovalRecord for an address.
func (rs *RecordStore) PutRemoval(ctx context.Context, rec *identity.AddressRemovalRecord) error {
	data, err := proto.Marshal(rec.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal removal: %w", err)
	}
	return rs.put(ctx, recRemovalPrefix, rec.Address, data)
}

// GetRemovalBytes returns the marshaled removal record for an address, or (nil, nil) when absent.
func (rs *RecordStore) GetRemovalBytes(ctx context.Context, address string) ([]byte, error) {
	return rs.get(ctx, recRemovalPrefix, address)
}

// --- Credential blocklists (keyed by domain) ---

// PutBlocklist stores the signed CredentialBlockList for a domain.
func (rs *RecordStore) PutBlocklist(ctx context.Context, bl *identity.CredentialBlockList) error {
	data, err := proto.Marshal(bl.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal blocklist: %w", err)
	}
	return rs.put(ctx, recBlocklistPrefix, bl.Domain, data)
}

// GetBlocklistBytes returns the marshaled blocklist for a domain, or (nil, nil) when absent.
func (rs *RecordStore) GetBlocklistBytes(ctx context.Context, domain string) ([]byte, error) {
	return rs.get(ctx, recBlocklistPrefix, domain)
}

// --- Fleet roster (keyed by fleet domain) ---

// PutRoster stores the signed FleetRoster for a fleet domain.
func (rs *RecordStore) PutRoster(ctx context.Context, roster *identity.FleetRoster) error {
	data, err := proto.Marshal(roster.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal roster: %w", err)
	}
	return rs.put(ctx, recRosterPrefix, roster.FleetDomain, data)
}

// GetRosterBytes returns the marshaled roster for a fleet domain, or (nil, nil) when absent.
func (rs *RecordStore) GetRosterBytes(ctx context.Context, fleetDomain string) ([]byte, error) {
	return rs.get(ctx, recRosterPrefix, fleetDomain)
}

// --- Relay onion descriptors (keyed by peer ID) ---

// PutRelayDescriptor stores a signed RelayDescriptor keyed by its peer ID.
func (rs *RecordStore) PutRelayDescriptor(ctx context.Context, desc *identity.RelayDescriptor) error {
	data, err := proto.Marshal(desc.ToProto())
	if err != nil {
		return fmt.Errorf("recordstore: marshal relay descriptor: %w", err)
	}
	return rs.put(ctx, recDescriptorPrefix, desc.PeerID, data)
}

// GetRelayDescriptorBytes returns the marshaled descriptor for a peer ID, or (nil, nil) when absent.
func (rs *RecordStore) GetRelayDescriptorBytes(ctx context.Context, peerID string) ([]byte, error) {
	return rs.get(ctx, recDescriptorPrefix, peerID)
}

// PutMarshaled parses and stores a marshaled record of the given kind. It does NOT re-verify —
// used for LOCAL replication by an authoritative pusher storing a record it just built/verified.
// The remote-push path (handlePutRecord) does the verification + anti-rollback.
func (rs *RecordStore) PutMarshaled(ctx context.Context, kind dmcnpb.RecordKind, data []byte) error {
	switch kind {
	case dmcnpb.RecordKind_RECORD_KIND_IDENTITY:
		rec, err := identity.IdentityRecordFromProtoBytes(data)
		if err != nil {
			return err
		}
		return rs.PutIdentity(ctx, rec)
	case dmcnpb.RecordKind_RECORD_KIND_DAR:
		dar, err := identity.DomainAuthorityRecordFromProtoBytes(data)
		if err != nil {
			return err
		}
		return rs.PutDAR(ctx, dar)
	case dmcnpb.RecordKind_RECORD_KIND_ROSTER:
		roster, err := identity.FleetRosterFromProtoBytes(data)
		if err != nil {
			return err
		}
		return rs.PutRoster(ctx, roster)
	case dmcnpb.RecordKind_RECORD_KIND_REMOVAL:
		rm, err := identity.AddressRemovalRecordFromProtoBytes(data)
		if err != nil {
			return err
		}
		return rs.PutRemoval(ctx, rm)
	case dmcnpb.RecordKind_RECORD_KIND_BLOCKLIST:
		bl, err := identity.CredentialBlockListFromProtoBytes(data)
		if err != nil {
			return err
		}
		return rs.PutBlocklist(ctx, bl)
	default:
		return fmt.Errorf("recordstore: unknown record kind %v", kind)
	}
}
