package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/bridge"
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
	peerFlag := addPeerIDFlag(fs, "the node's libp2p peer ID (run `dmcnd peer-id` on the node)")
	out := fs.String("out", "bridge.cred", "file to write the credential to")
	notAfter := fs.Duration("valid-for", 0, "how long the credential is valid (0 = no expiry)")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	peerID, err := peerFlag.value()
	if err != nil {
		return err
	}
	if peerID == "" {
		return fmt.Errorf("--peer-id is required — run `dmcnd peer-id` on the node")
	}

	subject, err := pubKeyFromPeerID(peerID)
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

	fmt.Printf("wrote %s — bridge credential for %s on %s\n", *out, peerID, *domain)
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

// cmdBridgeVerifyAudit re-verifies a bridge audit log that has been copied off the node.
//
// The bridge writes a hash-chained, signed record of every classification and delivery decision
// it makes. That is worth little if nobody can check it, and until now nothing shipped could:
// VerifyAuditLog existed as library code with no caller, so an operator could read the log but
// not establish that it had not been edited.
//
// The trusted key comes from the node's PEER ID, never from the log. An Ed25519 peer ID contains
// its public key, and that ID is already public — it is in the domain's _dmcn seed= record — so
// the operator is comparing the log against something they and every correspondent can see. A
// signature checked against a key taken from the file it is meant to authenticate proves nothing.
func cmdBridgeVerifyAudit(args []string) error {
	fs := flag.NewFlagSet("bridge verify-audit", flag.ExitOnError)
	logPath := fs.String("log", "", "path to the audit log (copy it off the node first)")
	peerFlag := addPeerIDFlag(fs, "peer ID of the bridge node whose key signed the log")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *logPath == "" {
		return fmt.Errorf("--log is required — the audit log to check, e.g. `docker cp dmcnd:/data/bridge-audit.log .`")
	}

	// A nil key verifies the chain but not the signatures, which is a materially weaker claim:
	// it catches edits, reordering and deletions, but not an attacker who rewrote the whole file.
	// Allowed, because someone reviewing a third party's log may not have the peer ID — but never
	// silently, or the weaker check gets mistaken for the stronger one.
	peerID, err := peerFlag.value()
	if err != nil {
		return err
	}
	var pub ed25519.PublicKey
	if peerID != "" {
		if pub, err = pubKeyFromPeerID(peerID); err != nil {
			return err
		}
	}

	n, err := bridge.VerifyAuditLog(*logPath, pub)
	if err != nil {
		if errors.Is(err, bridge.ErrAuditTampered) {
			return fmt.Errorf("AUDIT LOG FAILED VERIFICATION after %d good record(s): %w\n"+
				"  The chain or a signature does not hold, so this file is not the log the bridge wrote.\n"+
				"  Treat it as evidence of tampering, not as a corrupt file to repair", n, err)
		}
		return err
	}

	if pub == nil {
		fmt.Printf("chain intact: %d records, sequence contiguous and every link recomputed.\n", n)
		fmt.Fprintln(os.Stderr,
			"\nWARNING: signatures were NOT checked, because no --peer-id was given. This proves the file\n"+
				"was not edited in place, but NOT that the bridge wrote it — anyone can produce a\n"+
				"self-consistent chain. Re-run with --peer-id <peerID> for that.")
		return nil
	}
	fmt.Printf("verified: %d records, chain intact and every signature made by %s.\n", n, peerID)
	// Stated because it is the one gap the format cannot close on its own: nothing inside a log
	// records how long it should be, so records removed from the END leave a valid shorter log.
	fmt.Println("Note: truncation of the most recent records cannot be detected from the file alone.")
	return nil
}

// peerIDFlag registers --peer-id, plus --peer as a deprecated alias.
//
// The alias exists because --peer was the original name and it is in published docs. The rename
// is worth the churn: this CLI also has --peers, which takes a comma-separated list of MULTIADDRS
// for dialling a running daemon, while this one takes a bare peer ID and never dials anything.
// Two flags one character apart meaning entirely different things is a trap, and it caught its
// own author.
type peerIDFlag struct{ id, deprecated *string }

func addPeerIDFlag(fs *flag.FlagSet, usage string) peerIDFlag {
	return peerIDFlag{
		id:         fs.String("peer-id", "", usage),
		deprecated: fs.String("peer", "", "deprecated alias for --peer-id"),
	}
}

// value resolves the two spellings, refusing a contradiction rather than silently picking one.
func (p peerIDFlag) value() (string, error) {
	switch {
	case *p.id != "" && *p.deprecated != "" && *p.id != *p.deprecated:
		return "", fmt.Errorf("--peer-id and --peer are the same flag but were given different values (%q and %q)", *p.id, *p.deprecated)
	case *p.id != "":
		return *p.id, nil
	case *p.deprecated != "":
		fmt.Fprintln(os.Stderr, "dmcndcli: --peer is deprecated; use --peer-id (it is a peer ID, not the --peers multiaddr list)")
		return *p.deprecated, nil
	}
	return "", nil
}
