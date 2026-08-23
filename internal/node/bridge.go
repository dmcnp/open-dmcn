package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// bridge.go is how a sender finds the machine that will carry its mail out to the legacy email
// world — the DMCN analogue of an MX lookup.
//
// A bridge has no DMCN address, so there is nothing to resolve in the directory. Instead the
// domain advertises `bridge=` endpoints in its `_dmcn` TXT record, and each candidate proves
// itself with a `bridge` credential carried in its self-anchored RelayDescriptor. DNS discovers;
// the credential decides.
//
// That split matters more here than for `seed=`. A relay only ever holds sealed envelopes, but a
// bridge must DECRYPT outbound mail in order to hand it to SMTP — so whoever answers a bridge=
// token reads the plaintext. The credential check is therefore a confidentiality boundary, not a
// routing convenience, and it happens before anything is sealed to the candidate.

// BridgeEndpoint is a discovered, credential-verified outbound bridge: the peer to STORE
// outbound-to-legacy mail to, and the X25519 key to seal that mail under.
type BridgeEndpoint struct {
	PeerID       string   // libp2p peer ID (the STORE target)
	Multiaddr    string   // the /p2p/ multiaddr from the _dmcn bridge= token
	X25519Public [32]byte // seal outbound envelopes to this
}

// ResolveBridge discovers a credential-verified outbound bridge for senderDomain.
//
// It reads the domain's `_dmcn` `bridge=` endpoints, resolves each candidate's self-anchored
// RelayDescriptor by peer ID, and returns the first whose `bridge` credential verifies. A
// candidate that cannot present one is skipped, not trusted: the errors are collected so the
// caller can say why nothing worked rather than just that nothing did.
func (n *Node) ResolveBridge(ctx context.Context, senderDomain string) (*BridgeEndpoint, error) {
	rec, err := n.resolveDomain(ctx, senderDomain)
	if err != nil {
		return nil, fmt.Errorf("resolve _dmcn for %s: %w", senderDomain, err)
	}
	if len(rec.Bridges) == 0 {
		return nil, fmt.Errorf("domain %s advertises no bridge= endpoint in its _dmcn record, so it cannot send to legacy email", senderDomain)
	}

	var lastErr error
	for _, ma := range rec.Bridges {
		info, perr := ParseRelayHint(ma)
		if perr != nil {
			lastErr = fmt.Errorf("bad bridge multiaddr %q: %w", ma, perr)
			continue
		}
		// The bridge is often THIS process — a single-binary self-host is its own relay and its
		// own bridge. A host cannot dial itself, so answer from local state rather than going
		// out to the network to be told about ourselves. Nothing is skipped by doing so: the
		// credential check below exists to establish a REMOTE peer's authority, and our own is
		// whatever we were configured with.
		if n.host != nil && info.ID == n.host.ID() {
			return &BridgeEndpoint{PeerID: info.ID.String(), Multiaddr: ma, X25519Public: n.relayX25519Pub}, nil
		}
		// Connect first so the descriptor fetch — and the STORE that follows — can reach it.
		if cerr := n.ConnectPeer(ma); cerr != nil {
			lastErr = fmt.Errorf("connect bridge %s: %w", info.ID, cerr)
			continue
		}
		desc, derr := n.ResolveRelayDescriptor(ctx, info.ID.String())
		if derr != nil {
			lastErr = fmt.Errorf("resolve bridge descriptor %s: %w", info.ID, derr)
			continue
		}
		if verr := n.verifyBridgeCredential(ctx, desc, info.ID); verr != nil {
			lastErr = fmt.Errorf("bridge %s failed credential verification: %w", info.ID, verr)
			continue
		}
		return &BridgeEndpoint{PeerID: desc.PeerID, Multiaddr: ma, X25519Public: desc.X25519Public}, nil
	}
	return nil, fmt.Errorf("no usable bridge for %s: %w", senderDomain, lastErr)
}

// verifyBridgeCredential confirms a resolved descriptor belongs to a bridge its domain authorised.
//
// The descriptor is already self-anchored — ResolveRelayDescriptor checked its signature against
// the peer ID's own key — so the remaining questions are whether the credential is genuine, whether
// it grants `bridge`, and whether it is for THIS peer. The last is what stops a candidate copying
// a real bridge's credential, which is public and travels in every message that bridge signs.
func (n *Node) verifyBridgeCredential(ctx context.Context, desc *identity.RelayDescriptor, pid peer.ID) error {
	if desc.Credential == nil {
		return fmt.Errorf("descriptor carries no credential")
	}
	// The credential must name the peer we actually resolved.
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("peer ID does not carry its public key: %w", err)
	}
	raw, err := pub.Raw()
	if err != nil {
		return fmt.Errorf("extract peer public key: %w", err)
	}
	if !bytes.Equal(raw, desc.Credential.Subject) {
		return fmt.Errorf("credential subject is not this peer")
	}
	if !desc.Credential.HasRole(identity.RoleBridge) {
		return fmt.Errorf("credential does not carry the bridge role")
	}

	// Anchor it. A fleet deployment signs bridge credentials with the operator root; a
	// self-hosted domain signs them with its own DAR root. Try the configured operator key
	// first, then our own DAR, then resolve the credential's domain — the same ladder relay
	// selection uses (see onionsend.go).
	if len(n.operatorPub) == ed25519.PublicKeySize && bytes.Equal(desc.Credential.IssuerPub, n.operatorPub) {
		return identity.VerifyFleetCredential(desc.Credential, n.operatorPub, time.Now())
	}
	if n.credentialDAR != nil && desc.Credential.Domain == n.credentialDAR.Domain {
		return n.registry.VerifyCredentialWithDAR(ctx, desc.Credential, n.credentialDAR)
	}
	return n.registry.VerifyCredential(ctx, desc.Credential)
}
