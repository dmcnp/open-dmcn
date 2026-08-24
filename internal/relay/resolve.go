package relay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// resolveIdentity looks up an address's IdentityRecord LOCAL-FIRST: a serving relay is
// authoritative for the addresses it hosts, so it answers from its own RecordStore before falling
// back to the injected LookupFunc (the fleet resolver) for remote addresses. This avoids a
// network round-trip for the relay's own accounts.
func (r *Relay) resolveIdentity(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	if r.records != nil {
		if rec, err := r.records.GetIdentity(ctx, address); err == nil && rec != nil {
			return rec, nil
		}
	}
	return r.lookup(ctx, address)
}

// Fleet-resolution op handlers. Each serves a self-authenticating signed
// record from the node's local authoritative RecordStore. They are public, unauthenticated reads:
// the record carries its own signature, so a reader verifies it against the domain's DNS
// fingerprint — the node serving it is untrusted transport, never a trust root. A node with no
// record store, or without the requested record, answers found=false.

// resolveTimeout bounds a single record-store read.
const resolveTimeout = 10 * time.Second

// lookupRecordBytes runs get against the record store with a bounded context, returning nil bytes
// (found=false) when the store is absent or the record is missing.
func (r *Relay) lookupRecordBytes(get func(context.Context) ([]byte, error)) []byte {
	if r.records == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	data, err := get(ctx)
	if err != nil {
		r.log.Debugf("relay: resolve read failed: %v", err)
		return nil
	}
	return data
}

func (r *Relay) handleGetIdentity(req *dmcnpb.GetIdentityRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetIdentityBytes(ctx, req.GetAddress())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetIdentity{
		GetIdentity: &dmcnpb.GetIdentityResponse{Found: data != nil, Record: data},
	}}
}

func (r *Relay) handleGetDAR(req *dmcnpb.GetDARRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetDARBytes(ctx, req.GetDomain())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetDar{
		GetDar: &dmcnpb.GetDARResponse{Found: data != nil, Record: data},
	}}
}

func (r *Relay) handleGetFleetRoster(req *dmcnpb.GetFleetRosterRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetRosterBytes(ctx, req.GetFleetDomain())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetFleetRoster{
		GetFleetRoster: &dmcnpb.GetFleetRosterResponse{Found: data != nil, Record: data},
	}}
}

func (r *Relay) handleGetRemoval(req *dmcnpb.GetRemovalRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetRemovalBytes(ctx, req.GetAddress())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetRemoval{
		GetRemoval: &dmcnpb.GetRemovalResponse{Found: data != nil, Record: data},
	}}
}

func (r *Relay) handleGetBlocklist(req *dmcnpb.GetBlocklistRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetBlocklistBytes(ctx, req.GetDomain())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetBlocklist{
		GetBlocklist: &dmcnpb.GetBlocklistResponse{Found: data != nil, Record: data},
	}}
}

func (r *Relay) handleGetRelayDescriptor(req *dmcnpb.GetRelayDescriptorRequest) *dmcnpb.RelayResponse {
	data := r.lookupRecordBytes(func(ctx context.Context) ([]byte, error) {
		return r.records.GetRelayDescriptorBytes(ctx, req.GetPeerId())
	})
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_GetRelayDescriptor{
		GetRelayDescriptor: &dmcnpb.GetRelayDescriptorResponse{Found: data != nil, Record: data},
	}}
}

// --- Client side: fetch a signed record from a fleet node over libp2p. ---

// clientResolve opens a stream to peerID, sends req, and returns the response. A protocol-level
// ErrorResponse is surfaced as an error.
func (r *Relay) clientResolve(ctx context.Context, peerID peer.ID, req *dmcnpb.RelayRequest) (*dmcnpb.RelayResponse, error) {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return nil, fmt.Errorf("relay: resolve: open stream: %w", err)
	}
	defer s.Close()
	if err := writeRequest(s, req); err != nil {
		return nil, fmt.Errorf("relay: resolve: write: %w", err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: resolve: read: %w", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, fmt.Errorf("relay: resolve: %s: %s", e.GetCode(), e.GetMessage())
	}
	return resp, nil
}

// ClientGetIdentity fetches the signed IdentityRecord bytes for an address from a fleet node.
// Returns (nil, nil) when the node reports not-found.
func (r *Relay) ClientGetIdentity(ctx context.Context, peerID peer.ID, address string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetIdentity{GetIdentity: &dmcnpb.GetIdentityRequest{Address: address}},
	})
	if err != nil {
		return nil, err
	}
	gi := resp.GetGetIdentity()
	if gi == nil {
		return nil, errors.New("relay: resolve identity: unexpected response type")
	}
	if !gi.GetFound() {
		return nil, nil
	}
	return gi.GetRecord(), nil
}

// ClientGetDAR fetches the signed DomainAuthorityRecord bytes for a domain from a fleet node.
func (r *Relay) ClientGetDAR(ctx context.Context, peerID peer.ID, domain string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetDar{GetDar: &dmcnpb.GetDARRequest{Domain: domain}},
	})
	if err != nil {
		return nil, err
	}
	gd := resp.GetGetDar()
	if gd == nil {
		return nil, errors.New("relay: resolve dar: unexpected response type")
	}
	if !gd.GetFound() {
		return nil, nil
	}
	return gd.GetRecord(), nil
}

// ClientGetFleetRoster fetches the signed FleetRoster bytes for a fleet domain from a fleet node.
func (r *Relay) ClientGetFleetRoster(ctx context.Context, peerID peer.ID, fleetDomain string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetFleetRoster{GetFleetRoster: &dmcnpb.GetFleetRosterRequest{FleetDomain: fleetDomain}},
	})
	if err != nil {
		return nil, err
	}
	gr := resp.GetGetFleetRoster()
	if gr == nil {
		return nil, errors.New("relay: resolve roster: unexpected response type")
	}
	if !gr.GetFound() {
		return nil, nil
	}
	return gr.GetRecord(), nil
}

// ClientGetRemoval fetches the signed AddressRemovalRecord bytes for an address from a fleet node.
func (r *Relay) ClientGetRemoval(ctx context.Context, peerID peer.ID, address string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetRemoval{GetRemoval: &dmcnpb.GetRemovalRequest{Address: address}},
	})
	if err != nil {
		return nil, err
	}
	gr := resp.GetGetRemoval()
	if gr == nil {
		return nil, errors.New("relay: resolve removal: unexpected response type")
	}
	if !gr.GetFound() {
		return nil, nil
	}
	return gr.GetRecord(), nil
}

// ClientGetBlocklist fetches the signed CredentialBlockList bytes for a domain from a fleet node.
func (r *Relay) ClientGetBlocklist(ctx context.Context, peerID peer.ID, domain string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetBlocklist{GetBlocklist: &dmcnpb.GetBlocklistRequest{Domain: domain}},
	})
	if err != nil {
		return nil, err
	}
	gb := resp.GetGetBlocklist()
	if gb == nil {
		return nil, errors.New("relay: resolve blocklist: unexpected response type")
	}
	if !gb.GetFound() {
		return nil, nil
	}
	return gb.GetRecord(), nil
}

// ClientGetRelayDescriptor fetches a relay's marshaled onion descriptor from a fleet node
// (typically the descriptor's own node). Returns (nil, nil) when not found.
func (r *Relay) ClientGetRelayDescriptor(ctx context.Context, peerID peer.ID, target string) ([]byte, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_GetRelayDescriptor{GetRelayDescriptor: &dmcnpb.GetRelayDescriptorRequest{PeerId: target}},
	})
	if err != nil {
		return nil, err
	}
	gd := resp.GetGetRelayDescriptor()
	if gd == nil {
		return nil, errors.New("relay: resolve relay descriptor: unexpected response type")
	}
	if !gd.GetFound() {
		return nil, nil
	}
	return gd.GetRecord(), nil
}
