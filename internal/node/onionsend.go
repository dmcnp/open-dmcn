package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/core/onion"
)

// onionPacketTTL bounds how long an onion packet is valid in flight.
const onionPacketTTL = 5 * time.Minute

// RelayDirectory gathers RelayDescriptors for the relays this node can route onion traffic
// through. Candidates are the currently-connected peers + the configured infra peers (a client
// seeded with the full DMCN_NODE_PEERS list reaches the whole fleet); each candidate's descriptor
// is fetched from its own node via the fleet op. (There is no global relay enumeration;
// enumerating relays this node never connected to via the fleet roster is deferred.)
//
// In credential mode each candidate must carry a valid `node` credential bound to its own
// peer ID (the relay-trust gate sits at route selection rather than at peer admission)
// and must not belong to a blocked domain. Best-effort: unreachable/invalid peers are
// skipped.
func (n *Node) RelayDirectory(ctx context.Context) []identity.RelayDescriptor {
	seen := map[string]bool{}
	var out []identity.RelayDescriptor
	add := func(idStr string) {
		if idStr == "" || seen[idStr] {
			return
		}
		seen[idStr] = true
		d, err := n.ResolveRelayDescriptor(ctx, idStr)
		if err != nil {
			return
		}
		// Credential PKI: trust a relay iff its descriptor carries a valid `node` credential
		// whose Subject is its own peer ID.
		if n.credential != nil {
			if !n.relayCredentialValid(ctx, d) {
				n.log.Debugf("relay directory: skip %s: invalid/absent node credential", idStr)
				return
			}
			if d.Credential != nil && n.blockedDomains[strings.ToLower(d.Credential.Domain)] {
				return
			}
		}
		out = append(out, *d)
	}
	// Relay candidates: currently-connected peers + the configured seed list. (A global
	// provider enumeration was removed; the fleet roster is the future source of the full set.)
	for _, p := range n.host.Network().Peers() {
		add(p.String())
	}
	for _, hint := range n.peers {
		if info, err := ParseRelayHint(hint); err == nil {
			add(info.ID.String())
		}
	}
	return out
}

// relayCredentialValid reports whether a relay descriptor carries a valid `node`
// credential bound to its own peer ID (so it cannot be swapped from another relay), with
// the credential chaining to its domain's DNS-anchored root + not revoked.
func (n *Node) relayCredentialValid(ctx context.Context, d *identity.RelayDescriptor) bool {
	if d.Credential == nil || !d.Credential.HasRole(identity.RoleNode) {
		return false
	}
	pid, err := peer.Decode(d.PeerID)
	if err != nil {
		return false
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return false
	}
	raw, err := pub.Raw()
	if err != nil || !bytes.Equal(raw, d.Credential.Subject) {
		return false
	}
	// Fleet credential: a relay's `node` credential chains DIRECTLY to the config-anchored
	// operator root (no DAR), so verify it against the configured operator pubkey — mirroring
	// admitPresented. Fleet node creds have no domain, so the DAR paths below cannot verify them.
	if len(n.operatorPub) == ed25519.PublicKeySize && bytes.Equal(d.Credential.IssuerPub, n.operatorPub) {
		return identity.VerifyFleetCredential(d.Credential, n.operatorPub, time.Now()) == nil
	}
	// Same-domain relays verify against our own (DNS-anchored) DAR — no remote DAR fetch
	// needed, which keeps single-domain clusters working without a published DAR. Other
	// domains fall back to fetching their DAR from their own fleet.
	if n.credentialDAR != nil && d.Credential.Domain == n.credentialDAR.Domain {
		return n.registry.VerifyCredentialWithDAR(ctx, d.Credential, n.credentialDAR) == nil
	}
	return n.registry.VerifyCredential(ctx, d.Credential) == nil
}

// SendOnion delivers a (split) envelope to the recipient via a fixed 3-hop onion
// route whose exit is the recipient's relay. relaxed drops subnet diversity for
// small dev clusters. There is no silent downgrade to direct delivery — if a route
// can't be built or forwarded, it errors. Returns the envelope hash on success.
func (n *Node) SendOnion(ctx context.Context, senderAddr string, senderKP *identity.IdentityKeyPair, recipientRec *identity.IdentityRecord, env *message.EncryptedEnvelope, relaxed bool) ([32]byte, error) {
	// The exit runs the recipient's final STORE — sign it as the sender, exactly
	// like a direct STORE, so acceptEnvelope verifies it identically.
	envBytes, err := proto.Marshal(env.ToProto())
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	sig, err := crypto.Sign(senderKP.Ed25519Private, envHash[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("sign envelope: %w", err)
	}
	return n.SendOnionPreSigned(ctx, senderAddr, sig, recipientRec, env, relaxed)
}

// SendOnionPreSigned is SendOnion for a caller that already holds the sender's
// signature over the envelope hash (the web backend, where the browser signs and
// the server never has the user's key). The onion layers themselves use only
// ephemeral keys + relay public keys, so no user key material is involved here.
func (n *Node) SendOnionPreSigned(ctx context.Context, senderAddr string, senderSig []byte, recipientRec *identity.IdentityRecord, env *message.EncryptedEnvelope, relaxed bool) ([32]byte, error) {
	if len(recipientRec.RelayHints) == 0 {
		return [32]byte{}, fmt.Errorf("recipient has no relay hints")
	}

	envProto := env.ToProto()
	envBytes, err := proto.Marshal(envProto)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal envelope: %w", err)
	}
	envHash := crypto.SHA256Hash(envBytes)
	delivery, err := proto.Marshal(&dmcnpb.StoreRequest{
		SenderAddress:   senderAddr,
		SenderSignature: senderSig,
		Envelope:        envProto,
	})
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal delivery: %w", err)
	}

	candidates := n.RelayDirectory(ctx)
	byPeer := map[string]identity.RelayDescriptor{}
	for _, d := range candidates {
		byPeer[d.PeerID] = d
	}

	// Exit = the first relay hint with a published onion descriptor.
	var exitID string
	for _, hint := range recipientRec.RelayHints {
		info, perr := ParseRelayHint(hint)
		if perr != nil {
			continue
		}
		_ = n.ConnectPeer(hint)
		pid := info.ID.String()
		if _, ok := byPeer[pid]; !ok {
			d, lerr := n.ResolveRelayDescriptor(ctx, pid)
			if lerr != nil {
				continue
			}
			byPeer[pid] = *d
			candidates = append(candidates, *d)
		}
		exitID = pid
		break
	}
	if exitID == "" {
		return [32]byte{}, fmt.Errorf("no relay descriptor for the recipient's relay (onion key unavailable)")
	}

	// Build + forward, reselecting a fresh route on failure.
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		route, rerr := onion.SelectRoute(candidates, exitID, onion.RouteOptions{Relaxed: relaxed})
		if rerr != nil {
			return [32]byte{}, rerr
		}
		entry := route[0]
		entryID, derr := peer.Decode(entry.PeerID)
		if derr != nil {
			lastErr = derr
			continue
		}
		// Dial the entry via its advertised addrs.
		if d, ok := byPeer[entry.PeerID]; ok {
			for _, m := range d.Multiaddrs {
				if n.ConnectPeer(m) == nil {
					break
				}
			}
		}
		pkt, berr := onion.BuildOnion(route, delivery, time.Now().Add(onionPacketTTL))
		if berr != nil {
			return [32]byte{}, berr
		}
		if ferr := n.relay.ClientOnionForward(ctx, entryID, pkt); ferr != nil {
			lastErr = ferr
			n.log.Warnf("onion forward via entry %s failed: %v", entry.PeerID, ferr)
			continue
		}
		n.log.Debugf("onion send via %d-hop route, hash %x", len(route), envHash[:8])
		return envHash, nil
	}
	return [32]byte{}, fmt.Errorf("onion send failed after retries: %w", lastErr)
}
