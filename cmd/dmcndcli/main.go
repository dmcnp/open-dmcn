// Binary dmcndcli is the small standalone operator tool for a dmcnd deployment. The daemon does
// almost everything itself — it seeds its domain at boot and provisions accounts through the web UI
// — so this CLI covers only the few operator tasks that happen OUTSIDE the running process:
//
//	peer-id   print the libp2p peer ID for an identity key (for seed multiaddrs / peer allowlisting)
//	dns       print the _dmcn.<domain> TXT record the operator must publish for federation
//	remove-address
//	          root-sign a tombstone freeing an address, so it can be bound to a new key
//
// It reads the same on-disk state the daemon uses (the persistent identity key, the seed keystore),
// so its output matches what the daemon runs with.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
	"dmcn.dev/open-dmcn/internal/node"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "peer-id":
		err = cmdPeerID(os.Args[2:])
	case "dns":
		err = cmdDNS(os.Args[2:])
	case "remove-address":
		err = cmdRemoveAddress(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "dmcndcli: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dmcndcli:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dmcndcli — operator tool for a dmcnd deployment

Usage:
  dmcndcli peer-id --identity <path>
        Print the libp2p peer ID for an identity key (created if missing). Use it to build the
        node's seed multiaddr (/ip4/<host>/tcp/<port>/p2p/<peerID>) or to allowlist a peer.

  dmcndcli dns --domain <domain> [--data-dir <dir>] [--seed <multiaddr>]...
        Print the _dmcn.<domain> TXT record to publish in DNS so other domains can resolve and
        federate with yours. Reads the domain root key from the daemon's seed keystore.

  dmcndcli remove-address --address <local@domain> --peers <multiaddr>[,...] [--pubkey <hex>] [--yes]
        Root-sign and publish a tombstone for an address's current key, freeing the address to be
        registered again with a fresh key. This is the ONLY way to recover an address whose key was
        lost or compromised: the daemon refuses any record that re-binds a live address to a
        different key unless the domain root has tombstoned the incumbent. Reads the domain root key
        from the daemon's seed keystore, so it must run on the host holding it.

Environment: DMCND_IDENTITY, DMCND_DOMAIN, DMCND_DATA_DIR, DMCND_SEED_PASSPHRASE, DMCND_PEERS are
used as defaults for the matching flags.
`)
}

// cmdPeerID prints the peer ID for a persistent identity key, creating the key if it does not exist
// (matching the daemon's DMCND_IDENTITY behavior). Bare stdout so it composes in shell substitution.
func cmdPeerID(args []string) error {
	fs := flag.NewFlagSet("peer-id", flag.ExitOnError)
	identityPath := fs.String("identity", os.Getenv("DMCND_IDENTITY"), "path to the libp2p identity key file (created if missing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *identityPath == "" {
		return fmt.Errorf("--identity is required (or set DMCND_IDENTITY)")
	}
	priv, err := node.LoadOrCreateIdentityKey(*identityPath)
	if err != nil {
		return err
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("derive peer ID: %w", err)
	}
	fmt.Println(id.String())
	return nil
}

// cmdDNS prints the _dmcn.<domain> TXT record an operator publishes so other domains can resolve
// (and federate with) theirs: the DAR fingerprint (trust anchor) plus any seed multiaddrs.
func cmdDNS(args []string) error {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the DMCN domain this daemon serves")
	dataDir := fs.String("data-dir", envOr("DMCND_DATA_DIR", "data"), "daemon data dir (holds seed-keystore.json)")
	passphrase := fs.String("seed-passphrase", envOr("DMCND_SEED_PASSPHRASE", "dmcnd-dev-seed"), "seed keystore passphrase")
	var seeds multiFlag
	fs.Var(&seeds, "seed", "a public seed multiaddr ending in /p2p/<peerID> (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}

	fp, err := domainFingerprint(*dataDir, *passphrase, *domain)
	if err != nil {
		return err
	}

	fmt.Println(dmcnTXT(*domain, fp, seeds))
	if len(seeds) == 0 {
		fmt.Fprintf(os.Stderr, "\nfingerprint: %s\nnote: no --seed given — add your node's public seed multiaddr(s) so peers can dial it, e.g.\n  dmcndcli dns --domain %s --seed /ip4/<public-ip>/tcp/<port>/p2p/$(dmcndcli peer-id --identity <key>)\n", fp, *domain)
	}
	return nil
}

// domainFingerprint loads the domain root key from the daemon's seed keystore and returns its DAR
// fingerprint (the DNS trust anchor). The keystore path + root-key alias MUST match cmd/dmcnd/seed.go.
func domainFingerprint(dataDir, passphrase, domain string) (string, error) {
	ksPath := filepath.Join(dataDir, "seed-keystore.json")
	ks := keystore.New(ksPath, passphrase)
	root, err := ks.Load("__domain_root__@" + domain)
	if err != nil {
		return "", fmt.Errorf("load domain root key for %s from %s: %w\n(has the daemon seeded this domain? check --data-dir / --seed-passphrase)", domain, ksPath, err)
	}
	dar, err := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	if err != nil {
		return "", fmt.Errorf("build DAR: %w", err)
	}
	return dar.Fingerprint(), nil
}

// dmcnTXT renders the _dmcn.<domain> TXT record: the v1 verification prefix, the root-key
// fingerprint (fp=), and one seed= token per bootstrap multiaddr.
func dmcnTXT(domain, fp string, seeds []string) string {
	val := "dmcn-verification=v1; fp=" + fp
	for _, s := range seeds {
		val += "; seed=" + s
	}
	return fmt.Sprintf("_dmcn.%s.  TXT  %q", domain, val)
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	if v = strings.TrimSpace(v); v != "" {
		*m = append(*m, v)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
