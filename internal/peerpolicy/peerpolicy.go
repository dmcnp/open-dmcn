// Package peerpolicy decides whether a remote libp2p peer is permitted to
// federate with this node: connect (via the ConnectionGater), take part in
// peer discovery, and open relay streams. A single Policy instance is the
// source of truth for all three gates.
//
// This is a leaf package: it imports only the libp2p peer type so that the
// node, registry, and relay packages can all depend on it without import
// cycles. It performs no network I/O.
//
// Gating is by peer ID only. Domain-based node membership (trusting a peer by a
// DNS-anchored domain) was prototyped but deferred — it added more operational
// friction than per-peer-ID allowlists — so the policy decides purely on the
// authenticated peer ID.
package peerpolicy

import (
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerContext is what a gate knows about a peer at decision time. It carries the
// authenticated peer ID; it is a struct (rather than a bare peer.ID) to leave
// room for future decision inputs without churning the Policy interface.
type PeerContext struct {
	ID peer.ID
}

// Policy reports whether a peer may federate. Allow is called on hot paths
// (every dial, routing-table admission, and stream) so implementations must be
// cheap and safe for concurrent use.
type Policy interface {
	Allow(PeerContext) bool
	// Name identifies the policy for structured logging.
	Name() string
}

// AllowAll permits every peer. It is selected only by an explicit opt-in (the
// "*" allowlist sentinel); it is never the default.
type AllowAll struct{}

func (AllowAll) Allow(PeerContext) bool { return true }
func (AllowAll) Name() string           { return "allow-all" }

// AllowNone permits no peer. It is the default when no allow-set is configured
// — DMCN federation is deny-by-default.
type AllowNone struct{}

func (AllowNone) Allow(PeerContext) bool { return false }
func (AllowNone) Name() string           { return "allow-none" }

// PeerAllowList permits an explicit set of peer IDs. It is immutable after
// construction, so reads need no lock.
type PeerAllowList struct {
	ids map[peer.ID]struct{}
}

// NewPeerAllowList builds a PeerAllowList from the given peer IDs.
func NewPeerAllowList(ids []peer.ID) *PeerAllowList {
	m := make(map[peer.ID]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return &PeerAllowList{ids: m}
}

func (p *PeerAllowList) Allow(ctx PeerContext) bool {
	_, ok := p.ids[ctx.ID]
	return ok
}
func (p *PeerAllowList) Name() string { return "peer-allowlist" }
