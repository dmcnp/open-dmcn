package onion

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/multiformats/go-multiaddr"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// DefaultHops is the fixed onion route length (see whitepaper §15.4): entry knows
// the sender, exit knows the destination, the middle keeps them non-adjacent.
const DefaultHops = 3

// RouteOptions tunes route selection.
type RouteOptions struct {
	Hops int // 0 ⇒ DefaultHops
	// Relaxed drops the subnet-diversity constraint, keeping only distinct peers.
	// For small/dev networks (e.g. a 3-node localhost cluster) where every relay
	// shares a subnet/operator — the protocol property (middle sees neither end)
	// still holds; anonymity strengthens as the relay set diversifies.
	Relaxed bool
	// Guard, if set to a candidate's peer ID (and not the exit), pins that relay as
	// the entry hop. Reusing a stable guard across sends limits a user's exposure to
	// ever drawing a malicious entry (Tor's guard rationale). Persisting/rotating
	// the guard is the caller's concern (see the package doc — not done for the
	// ephemeral CLI; a long-lived client should hold one + rotate ~monthly).
	Guard string
}

// SelectRoute picks an onion route of opts.Hops relays ending at exitPeerID (the
// recipient's relay, which performs final delivery). The earlier hops are chosen
// at random from candidates with distinct peer IDs and — unless Relaxed — distinct
// /24 subnets. Errors if there aren't enough sufficiently-diverse relays.
func SelectRoute(candidates []identity.RelayDescriptor, exitPeerID string, opts RouteOptions) ([]Hop, error) {
	hops := opts.Hops
	if hops <= 0 {
		hops = DefaultHops
	}

	var exit *identity.RelayDescriptor
	pool := make([]identity.RelayDescriptor, 0, len(candidates))
	for i := range candidates {
		if candidates[i].PeerID == exitPeerID {
			exit = &candidates[i]
			continue
		}
		pool = append(pool, candidates[i])
	}
	if exit == nil {
		return nil, fmt.Errorf("onion: exit relay %s not among candidates", exitPeerID)
	}
	if len(pool)+1 < hops {
		return nil, fmt.Errorf("onion: need %d relays, have %d", hops, len(pool)+1)
	}

	if err := shuffleDescriptors(pool); err != nil {
		return nil, err
	}

	// Greedily fill the earlier hops, keeping the exit's peer/subnet/domain reserved.
	chosen := make([]identity.RelayDescriptor, 0, hops-1)
	usedPeers := map[string]bool{exit.PeerID: true}
	usedSubnets := map[string]bool{subnetOf(*exit): true}
	usedDomains := map[string]bool{}
	if exit.Domain != "" {
		usedDomains[exit.Domain] = true
	}

	// Pin the guard as the entry hop when requested and available.
	if hops > 1 && opts.Guard != "" && opts.Guard != exitPeerID {
		for i := range pool {
			if pool[i].PeerID == opts.Guard {
				chosen = append(chosen, pool[i])
				usedPeers[pool[i].PeerID] = true
				usedSubnets[subnetOf(pool[i])] = true
				if pool[i].Domain != "" {
					usedDomains[pool[i].Domain] = true
				}
				pool = append(pool[:i], pool[i+1:]...)
				break
			}
		}
	}

	for i := range pool {
		if len(chosen) == hops-1 {
			break
		}
		c := pool[i]
		if usedPeers[c.PeerID] {
			continue
		}
		// Diversity (skipped in Relaxed mode for small/single-operator clusters):
		// distinct /24 subnets AND distinct domains, so no two hops share an
		// operator — the property that keeps the middle hop from colluding with
		// either end (whitepaper §15.4.4 operator diversity; domain = operator).
		if !opts.Relaxed {
			if usedSubnets[subnetOf(c)] {
				continue
			}
			if c.Domain != "" && usedDomains[c.Domain] {
				continue
			}
		}
		chosen = append(chosen, c)
		usedPeers[c.PeerID] = true
		usedSubnets[subnetOf(c)] = true
		if c.Domain != "" {
			usedDomains[c.Domain] = true
		}
	}
	if len(chosen) < hops-1 {
		return nil, fmt.Errorf("onion: could not select %d sufficiently-diverse relays (relaxed=%t)", hops, opts.Relaxed)
	}

	route := make([]Hop, 0, hops)
	for _, d := range chosen {
		route = append(route, Hop{PeerID: d.PeerID, X25519Pub: d.X25519Public})
	}
	route = append(route, Hop{PeerID: exit.PeerID, X25519Pub: exit.X25519Public})
	return route, nil
}

// subnetOf returns the relay's /24 (best-effort, from its first IPv4 multiaddr).
// An unknown subnet falls back to a peer-unique token so it never collides — an
// undiscoverable subnet shouldn't silently block diversity.
func subnetOf(d identity.RelayDescriptor) string {
	for _, m := range d.Multiaddrs {
		ma, err := multiaddr.NewMultiaddr(m)
		if err != nil {
			continue
		}
		if ip, err := ma.ValueForProtocol(multiaddr.P_IP4); err == nil {
			if i := strings.LastIndex(ip, "."); i > 0 {
				return ip[:i]
			}
		}
	}
	return "peer:" + d.PeerID
}

// shuffleDescriptors does a crypto/rand Fisher–Yates shuffle in place.
func shuffleDescriptors(s []identity.RelayDescriptor) error {
	for i := len(s) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("onion: route shuffle: %w", err)
		}
		j := int(jBig.Int64())
		s[i], s[j] = s[j], s[i]
	}
	return nil
}
