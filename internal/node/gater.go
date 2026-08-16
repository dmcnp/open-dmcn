package node

import (
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"

	"dmcn.dev/open-dmcn/internal/peerpolicy"
)

// policyGater is a libp2p ConnectionGater backed by a peerpolicy.Policy. It is
// the connection-level enforcement of federation membership: peers the policy
// rejects are never dialed and inbound connections from them are torn down.
type policyGater struct {
	policy peerpolicy.Policy
}

func newPolicyGater(p peerpolicy.Policy) *policyGater { return &policyGater{policy: p} }

// Compile-time assertion that policyGater satisfies the gater interface, so a
// libp2p signature change surfaces here rather than at the call site.
var _ connmgr.ConnectionGater = (*policyGater)(nil)

func (g *policyGater) allow(p peer.ID) bool {
	return g.policy.Allow(peerpolicy.PeerContext{ID: p})
}

// InterceptPeerDial gates outbound dials by peer ID (known here).
func (g *policyGater) InterceptPeerDial(p peer.ID) bool { return g.allow(p) }

// InterceptAddrDial gates outbound dials per address; redundant with
// InterceptPeerDial but enforced for completeness.
func (g *policyGater) InterceptAddrDial(p peer.ID, _ multiaddr.Multiaddr) bool { return g.allow(p) }

// InterceptAccept runs before the security handshake, when no authenticated
// peer ID is available, so it cannot enforce the policy — it always allows and
// defers to InterceptSecured.
func (g *policyGater) InterceptAccept(_ network.ConnMultiaddrs) bool { return true }

// InterceptSecured runs after the security handshake has cryptographically
// proven the remote's peer ID. This is the primary inbound enforcement point.
func (g *policyGater) InterceptSecured(_ network.Direction, p peer.ID, _ network.ConnMultiaddrs) bool {
	return g.allow(p)
}

// InterceptUpgraded is a final defense-in-depth check once the connection is
// fully established. The DisconnectReason is currently ignored by go-libp2p.
func (g *policyGater) InterceptUpgraded(c network.Conn) (bool, control.DisconnectReason) {
	return g.allow(c.RemotePeer()), 0
}

// buildPeerPolicy constructs the node's federation Policy from its config.
//
// The allow-set is seeded from the explicit AllowedPeers plus the
// operator-configured Peers — peers you explicitly configured are implicitly
// trusted. With nothing configured the result is AllowNone (deny-by-default).
// A single "*" entry in AllowedPeers opts into AllowAll (intentionally-open
// deployments and tests). In Credential-PKI mode this static allow-set is only
// an escape hatch; trust otherwise comes from credentials presented at /dmcn/join.
func buildPeerPolicy(cfg Config) (peerpolicy.Policy, error) {
	for _, e := range cfg.AllowedPeers {
		if strings.TrimSpace(e) == "*" {
			return peerpolicy.AllowAll{}, nil
		}
	}

	idSet := make(map[peer.ID]struct{})
	// Explicit allowlist entries are strict: a malformed entry is a config error. This static
	// allow-set is only the dev/escape-hatch layer inside credentialPolicy — real trust is the
	// credential presented at /dmcn/join. `cfg.Peers` is NOT auto-trusted: it is bootstrap /
	// discovery only (where to dial), never a trust assertion. A peer earns participation by
	// presenting a valid credential, not by being a configured bootstrap peer.
	for _, e := range cfg.AllowedPeers {
		if strings.TrimSpace(e) == "" {
			continue
		}
		id, err := peerIDFromEntry(e)
		if err != nil {
			return nil, fmt.Errorf("node: allowed peer %q: %w", e, err)
		}
		idSet[id] = struct{}{}
	}

	if len(idSet) == 0 {
		return peerpolicy.AllowNone{}, nil
	}
	ids := make([]peer.ID, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	return peerpolicy.NewPeerAllowList(ids), nil
}

// peerIDFromEntry extracts a peer ID from an allowlist entry, which may be a
// full multiaddr (e.g. /ip4/.../p2p/<id>) or a bare base58 peer ID.
func peerIDFromEntry(entry string) (peer.ID, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", fmt.Errorf("empty entry")
	}
	if strings.HasPrefix(entry, "/") {
		info, err := ParseRelayHint(entry)
		if err != nil {
			return "", err
		}
		return info.ID, nil
	}
	id, err := peer.Decode(entry)
	if err != nil {
		return "", fmt.Errorf("invalid peer ID: %w", err)
	}
	return id, nil
}
