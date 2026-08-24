package node

import (
	"crypto/ed25519"
	"strings"
	"sync"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/peerpolicy"
)

// credentialSet is the in-memory set of peers that have presented a valid Credential at
// the /dmcn/join handshake, keeping each peer's whole verified credential for the life of
// the connection. Actions over the wire are authorized against the credential's roles and
// grants. It is the source of truth the re-closed federation gates consult — a pure
// in-memory check, so there is NO network I/O on the hot path.
//
// Credentials are kept in two distinct buckets by their trust ROOT, because the root decides
// what the credential may authorize (the three-layer trust chain):
//   - DOMAIN credentials chain to a DNS-anchored DAR; they authorize domain-scoped actions
//     (address issuance, placement) and are checked domain-scoped (`hasGrant` + CoversDomain).
//   - FLEET credentials chain directly to the config-anchored operator root; they authorize
//     fleet/infrastructure actions (reserve, drain, handoff, accounts) and are checked
//     fleet-scoped (`hasFleetGrant`). A domain credential's grant can NEVER authorize a fleet
//     op, and vice versa — that separation is the confused-deputy guard.
type credentialSet struct {
	mu sync.RWMutex
	// m keeps, per peer, all the DOMAIN credentials it presented (one per domain, keyed by
	// lowercased credential domain) so a peer credentialed in several domains is authorized
	// per target domain.
	m map[peer.ID]map[string]credEntry
	// fleet keeps, per peer, its single operator-rooted FLEET credential (membership +
	// fleet grants). Not domain-scoped.
	fleet map[peer.ID]credEntry
}

type credEntry struct {
	cred *identity.Credential
	at   time.Time
}

func newCredentialSet() *credentialSet {
	return &credentialSet{m: map[peer.ID]map[string]credEntry{}, fleet: map[peer.ID]credEntry{}}
}

// add records one of a peer's verified DOMAIN credentials (DAR-rooted), indexed by its domain
// (a re-join for the same domain overwrites; different domains accumulate).
func (s *credentialSet) add(id peer.ID, cred *identity.Credential) {
	if cred == nil {
		return
	}
	s.mu.Lock()
	if s.m[id] == nil {
		s.m[id] = map[string]credEntry{}
	}
	s.m[id][strings.ToLower(cred.Domain)] = credEntry{cred: cred, at: time.Now()}
	s.mu.Unlock()
}

// addFleet records a peer's operator-rooted FLEET credential (config-anchored, not
// domain-scoped). One per peer; a re-join overwrites.
func (s *credentialSet) addFleet(id peer.ID, cred *identity.Credential) {
	if cred == nil {
		return
	}
	s.mu.Lock()
	s.fleet[id] = credEntry{cred: cred, at: time.Now()}
	s.mu.Unlock()
}

// remove drops a peer entirely (e.g. on disconnect).
func (s *credentialSet) remove(id peer.ID) {
	s.mu.Lock()
	delete(s.m, id)
	delete(s.fleet, id)
	s.mu.Unlock()
}

// has reports whether the peer has presented at least one valid credential (domain or fleet).
func (s *credentialSet) has(id peer.ID) bool {
	s.mu.RLock()
	_, fleet := s.fleet[id]
	ok := len(s.m[id]) > 0 || fleet
	s.mu.RUnlock()
	return ok
}

// hasRole reports whether ANY of the peer's credentials (domain or fleet) carries role.
func (s *credentialSet) hasRole(id peer.ID, role string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.m[id] {
		if e.cred != nil && e.cred.HasRole(role) {
			return true
		}
	}
	if e, ok := s.fleet[id]; ok && e.cred != nil && e.cred.HasRole(role) {
		return true
	}
	return false
}

// hasFleetRole reports whether the peer's operator-rooted FLEET credential carries role
// (e.g. the handoff-inject `node` role — an infrastructure role, never domain-scoped).
func (s *credentialSet) hasFleetRole(id peer.ID, role string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.fleet[id]
	return ok && e.cred != nil && e.cred.HasRole(role)
}

// hasGrant reports whether the peer holds a DOMAIN credential carrying grant whose domain
// authority covers `domain` (the target the op acts on). Domain-scoped: a grant issued for
// one domain cannot authorize an action on another. Fail closed.
func (s *credentialSet) hasGrant(id peer.ID, grant, domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.m[id] {
		if e.cred != nil && e.cred.HasGrant(grant) && e.cred.CoversDomain(domain) {
			return true
		}
	}
	return false
}

// hasFleetGrant reports whether the peer holds an operator-rooted FLEET credential carrying
// grant. Fleet ops (reserve/drain/handoff/accounts) are authorized ONLY by a fleet grant —
// a domain credential's grant can never authorize a fleet op. Fail closed.
func (s *credentialSet) hasFleetGrant(id peer.ID, grant string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.fleet[id]
	return ok && e.cred != nil && e.cred.HasGrant(grant)
}

// hasFleetGrantForKey reports whether the peer identified by an Ed25519 public key holds an
// operator-rooted FLEET credential carrying grant. It derives the peer ID from the key (a
// libp2p ed25519 peer ID inlines its key), so a RoleQuota credential's issuer can be checked
// against the operator-delegated fleet grant it was signed under. Fail closed.
func (s *credentialSet) hasFleetGrantForKey(pub []byte, grant string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	pk, err := libp2pcrypto.UnmarshalEd25519PublicKey(pub)
	if err != nil {
		return false
	}
	id, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return false
	}
	return s.hasFleetGrant(id, grant)
}

// credential returns one of the peer's verified credentials (any domain, else fleet), or nil.
func (s *credentialSet) credential(id peer.ID) *identity.Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.m[id] {
		return e.cred
	}
	if e, ok := s.fleet[id]; ok {
		return e.cred
	}
	return nil
}

// credentialPolicy is a peerpolicy.Policy that admits a peer when it is in the static
// allow-set (the operator's escape hatch / explicit bootstrap) OR has presented a valid
// credential. With no static entries it is purely credential-gated (deny-by-default).
type credentialPolicy struct {
	static peerpolicy.Policy // may be AllowNone
	set    *credentialSet
}

func (p *credentialPolicy) Allow(ctx peerpolicy.PeerContext) bool {
	if p.static != nil && p.static.Allow(ctx) {
		return true
	}
	return p.set.has(ctx.ID)
}

func (p *credentialPolicy) Name() string { return "credential" }
