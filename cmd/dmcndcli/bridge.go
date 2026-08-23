package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// cmdBridgeIssue signs the credential that lets a node act as an SMTP bridge for a domain.
//
// A bridge has no DMCN email address. It is infrastructure — a peer that translates between SMTP
// and DMCN — and what recipients need is not a directory entry for it but proof that the domain's
// owner authorised that particular key to speak for the domain about legacy mail. This command
// produces exactly that: one root signature over the node's own public key.
//
// It needs nothing from the node but its peer ID, because an Ed25519 peer ID *contains* the public
// key. So this runs entirely offline, alongside `domain init`, with no round trip.
func cmdBridgeIssue(args []string) error {
	fs := flag.NewFlagSet("bridge issue", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the domain the bridge serves")
	peerID := fs.String("peer", "", "the node's libp2p peer ID (run `dmcnd peer-id` on the node)")
	out := fs.String("out", "bridge.cred", "file to write the credential to")
	notAfter := fs.Duration("valid-for", 0, "how long the credential is valid (0 = no expiry)")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	if *peerID == "" {
		return fmt.Errorf("--peer is required — run `dmcnd peer-id` on the node")
	}

	subject, err := pubKeyFromPeerID(*peerID)
	if err != nil {
		return err
	}
	root, err := rf.load(*domain)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	cred := &identity.Credential{
		Version:  1,
		Subject:  subject,
		Domain:   *domain,
		Roles:    []string{identity.RoleBridge},
		IssuedAt: now,
	}
	if *notAfter > 0 {
		cred.NotAfter = now.Add(*notAfter)
	}
	if err := cred.Sign(root); err != nil {
		return fmt.Errorf("sign the bridge credential: %w", err)
	}

	// Written in the same {credential, DAR} container the node already reads. No DAR: this one
	// is anchored directly on the domain root, which is what a recipient verifies it against.
	data, err := node.MarshalCredentialBundle(cred, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}

	fmt.Printf("wrote %s — bridge credential for %s on %s\n", *out, *peerID, *domain)
	fmt.Fprintf(os.Stderr, "\nCopy it to the node — it holds no private key — and set there:\n"+
		"    DMCND_BRIDGE_ENABLED=true\n"+
		"    DMCND_BRIDGE_CREDENTIAL=<path to %s on the node>\n", filepath.Base(*out))
	return nil
}

// pubKeyFromPeerID recovers the Ed25519 public key embedded in a peer ID.
//
// Ed25519 peer IDs are "identity" multihashes — the key is inside the ID rather than hashed into
// it — which is why issuing a bridge credential needs no contact with the node. A peer ID using a
// key type that does not embed its key (RSA) cannot be used, and that is worth saying plainly
// rather than failing with a decoding error.
func pubKeyFromPeerID(id string) (ed25519.PublicKey, error) {
	pid, err := peer.Decode(id)
	if err != nil {
		return nil, fmt.Errorf("parse peer ID %q: %w", id, err)
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil {
		return nil, fmt.Errorf("peer ID %s does not carry its public key (only Ed25519 peer IDs do): %w", id, err)
	}
	edPub, ok := pub.(*libp2pcrypto.Ed25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("peer ID %s is not an Ed25519 key; a bridge credential must name an Ed25519 subject", id)
	}
	b, err := edPub.Raw()
	if err != nil {
		return nil, fmt.Errorf("extract the raw public key: %w", err)
	}
	return ed25519.PublicKey(b), nil
}
