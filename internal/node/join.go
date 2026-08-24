package node

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	multiaddr "github.com/multiformats/go-multiaddr"
	"google.golang.org/protobuf/encoding/protodelim"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// JoinProtocol is the credential-presentation handshake (Credential PKI). On connect, a
// peer presents its Credential + the DAR that anchors it; the verifier checks it against
// a direct DNS resolution and admits the peer to the in-memory
// credentialSet, which gates federation participation.
const JoinProtocol = "/dmcn/join/1.0.0"

const joinTimeout = 10 * time.Second

// Admitted reports whether a peer is permitted to federate (participate) with this node —
// the deny-by-default participation gate. That
// is exactly the federation policy: the peer is in the static allow-set (the dev `*` / explicit
// bootstrap escape hatch) OR it presented a valid credential at /dmcn/join. With neither, false.
func (n *Node) Admitted(p peer.ID) bool {
	return n.allowPeer(p)
}

// startJoinService registers the join stream handler + a notifiee that initiates a join
// from the dialing side of every new connection. It also kicks off a join with peers that
// are already connected (e.g. an issuer that just provisioned us, or a bootstrap dial that
// completed before activation) — those predate the notifiee, so they need a one-shot push.
func (n *Node) startJoinService() {
	n.joinOnce.Do(func() {
		n.host.SetStreamHandler(JoinProtocol, n.handleJoin)
		n.host.Network().Notify(&joinNotifiee{n: n})
	})
	// Kick a join with peers already connected — they predate the notifiee, or we just gained a
	// credential on an inert→active transition. Safe to re-run: initiateJoin no-ops a peer we've
	// already admitted or have no credential to present to.
	for _, p := range n.host.Network().Peers() {
		go n.initiateJoin(p)
	}
}

// handleJoin (responder): read the dialer's JoinRequest, admit it, and reply with our
// own credential so the dialer admits us too (mutual join over one exchange).
func (n *Node) handleJoin(s network.Stream) {
	defer s.Close()
	remote := s.Conn().RemotePeer()
	var req dmcnpb.JoinRequest
	if err := protodelim.UnmarshalFrom(bufio.NewReader(s), &req); err != nil {
		return
	}
	resp := &dmcnpb.JoinResponse{}
	if err := n.admitJoin(remote, s.Conn().RemoteMultiaddr(), req.Bundles, req.Credential, req.Dar); err != nil {
		resp.Error = err.Error()
		n.log.Debugf("join: rejected %s: %v", remote, err)
	} else {
		resp.Accepted = true
	}
	resp.Credential, resp.Dar, resp.Bundles = n.ownJoinBundlesProto()
	_, _ = protodelim.MarshalTo(s, resp)
}

// ownJoinBundlesProto returns this node's {credential, DAR} bundles as proto (one per domain)
// plus the primary singular pair (for a single-domain peer on the other end).
func (n *Node) ownJoinBundlesProto() (primaryCred *dmcnpb.Credential, primaryDar *dmcnpb.DomainAuthorityRecord, bundles []*dmcnpb.CredentialBundle) {
	for _, b := range n.joinBundles {
		if b.Credential == nil {
			continue
		}
		// A fleet credential chains to the config operator root and carries no DAR; present it
		// with an empty Dar (the verifier routes by IssuerPub). Domain creds carry their DAR.
		pb := &dmcnpb.CredentialBundle{Credential: b.Credential.ToProto()}
		if b.DAR != nil {
			pb.Dar = b.DAR.ToProto()
		}
		bundles = append(bundles, pb)
	}
	if len(bundles) > 0 {
		primaryCred, primaryDar = bundles[0].Credential, bundles[0].Dar
	}
	return
}

// admitJoin verifies and records every presented bundle (falling back to the singular
// credential/dar for a single-domain peer). It succeeds if at least one bundle is admitted, so
// a peer credentialed in several domains is authorized per target domain.
func (n *Node) admitJoin(p peer.ID, observed multiaddr.Multiaddr, bundles []*dmcnpb.CredentialBundle, cred *dmcnpb.Credential, dar *dmcnpb.DomainAuthorityRecord) error {
	type pair struct {
		c *dmcnpb.Credential
		d *dmcnpb.DomainAuthorityRecord
	}
	var pairs []pair
	for _, b := range bundles {
		if b != nil {
			pairs = append(pairs, pair{b.Credential, b.Dar})
		}
	}
	if len(pairs) == 0 {
		pairs = append(pairs, pair{cred, dar})
	}
	var admitted int
	var lastErr error
	for _, pr := range pairs {
		if err := n.admitPresented(p, observed, pr.c, pr.d); err != nil {
			lastErr = err
			continue
		}
		admitted++
	}
	if admitted == 0 {
		if lastErr == nil {
			lastErr = errors.New("no credential presented")
		}
		return lastErr
	}
	return nil
}

// initiateJoin (dialer): present our credential and admit the peer's reply.
func (n *Node) initiateJoin(p peer.ID) {
	// Present our own credential(s) if we hold any — a fleet credential has no DAR. A
	// credential-less pure relay has nothing to present and only validates inbound.
	if n.credential == nil || n.credentials.has(p) {
		return
	}
	ctx, cancel := context.WithTimeout(n.ctx, joinTimeout)
	defer cancel()
	s, err := n.host.NewStream(ctx, p, JoinProtocol)
	if err != nil {
		return
	}
	defer s.Close()
	reqCred, reqDar, reqBundles := n.ownJoinBundlesProto()
	req := &dmcnpb.JoinRequest{Credential: reqCred, Dar: reqDar, Bundles: reqBundles}
	if _, err := protodelim.MarshalTo(s, req); err != nil {
		return
	}
	var resp dmcnpb.JoinResponse
	if err := protodelim.UnmarshalFrom(bufio.NewReader(s), &resp); err != nil {
		return
	}
	if resp.Credential != nil || len(resp.Bundles) > 0 {
		if err := n.admitJoin(p, s.Conn().RemoteMultiaddr(), resp.Bundles, resp.Credential, resp.Dar); err != nil {
			n.log.Debugf("join: could not admit %s: %v", p, err)
		}
	}
}

// admitPresented verifies a peer's presented {credential, DAR} and, on success, records
// its roles in the credentialSet. Checks: subject == the peer's proven key; the cred
// verifies against the bundled (DNS-anchored) DAR + blocklist; and, for infra roles, the
// observed connection IP matches the credential's advertised multiaddr/ip attribute.
func (n *Node) admitPresented(p peer.ID, observed multiaddr.Multiaddr, credPb *dmcnpb.Credential, darPb *dmcnpb.DomainAuthorityRecord) error {
	if credPb == nil {
		return errors.New("missing credential")
	}
	cred, err := identity.CredentialFromProto(credPb)
	if err != nil {
		return err
	}
	pub, err := p.ExtractPublicKey()
	if err != nil {
		return fmt.Errorf("extract peer key: %w", err)
	}
	raw, err := pub.Raw()
	if err != nil || !bytes.Equal(raw, cred.Subject) {
		return errors.New("credential subject does not match peer id")
	}

	// Fleet credential: chains DIRECTLY to the config-anchored operator root (no DAR). A peer
	// presenting a credential signed by the operator key is verified against the operator pubkey
	// and recorded as a fleet credential — it authorizes fleet/infra ops (fleet-scoped), never
	// domain ops.
	if len(n.operatorPub) == ed25519.PublicKeySize && bytes.Equal(cred.IssuerPub, n.operatorPub) {
		if err := identity.VerifyFleetCredential(cred, n.operatorPub, time.Now()); err != nil {
			return err
		}
		if isInfraRoles(cred.Roles) {
			if err := checkMultiaddrAttr(cred.Attributes, observed); err != nil {
				return err
			}
		}
		n.credentials.addFleet(p, cred)
		n.log.Debugf("join: admitted (fleet) %s roles=%v grants=%v", p, cred.Roles, cred.Grants)
		return nil
	}

	// Domain credential: DAR-anchored (DNS), verified against the bundled DAR + blocklist.
	if darPb == nil {
		return errors.New("missing DAR for domain credential")
	}
	dar, err := identity.DomainAuthorityRecordFromProto(darPb)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(n.ctx, joinTimeout)
	defer cancel()
	if err := n.registry.VerifyCredentialWithDAR(ctx, cred, dar); err != nil {
		return err
	}
	if isInfraRoles(cred.Roles) {
		if err := checkMultiaddrAttr(cred.Attributes, observed); err != nil {
			return err
		}
	}
	n.credentials.add(p, cred)
	n.log.Debugf("join: admitted (domain) %s roles=%v grants=%v", p, cred.Roles, cred.Grants)
	return nil
}

func isInfraRoles(roles []string) bool {
	for _, r := range roles {
		if r == identity.RoleNode || r == identity.RoleBridge {
			return true
		}
	}
	return false
}

// checkMultiaddrAttr enforces that the observed connection IP matches the credential's
// "ip" (or the IP in its "multiaddr") attribute when present. Lenient: a missing
// attribute or a non-IP transport skips the check (defence-in-depth, not primary auth).
func checkMultiaddrAttr(attrs map[string]string, observed multiaddr.Multiaddr) error {
	want := attrs["ip"]
	if want == "" {
		if m := attrs["multiaddr"]; m != "" {
			if mm, err := multiaddr.NewMultiaddr(m); err == nil {
				want, _ = mm.ValueForProtocol(multiaddr.P_IP4)
			}
		}
	}
	if want == "" || observed == nil {
		return nil
	}
	got, err := observed.ValueForProtocol(multiaddr.P_IP4)
	if err != nil {
		return nil
	}
	if got != want {
		return fmt.Errorf("credential ip %s != observed %s", want, got)
	}
	return nil
}

// joinNotifiee starts a join from the dialing side of each new connection and drops a
// fully-disconnected peer from the credentialSet (so a reconnect re-joins).
type joinNotifiee struct{ n *Node }

func (jn *joinNotifiee) Connected(_ network.Network, c network.Conn) {
	if c.Stat().Direction == network.DirOutbound {
		go jn.n.initiateJoin(c.RemotePeer())
	}
}
func (jn *joinNotifiee) Disconnected(net network.Network, c network.Conn) {
	p := c.RemotePeer()
	if len(net.ConnsToPeer(p)) == 0 {
		jn.n.credentials.remove(p)
	}
}
func (jn *joinNotifiee) Listen(network.Network, multiaddr.Multiaddr)      {}
func (jn *joinNotifiee) ListenClose(network.Network, multiaddr.Multiaddr) {}
