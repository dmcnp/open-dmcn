package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
	"dmcn.dev/open-dmcn/internal/node"
)

// domaininit.go is the offline ceremony that brings a domain into existence, and the push that
// hands the result to a node.
//
// They are separate commands on purpose. `init` touches no network and can run on a machine that
// never goes online; `publish` is the only step that talks to the node, and all it sends is a
// signed public record. The root key stays here for both.

// cmdDomainInit mints the domain root key and signs its authority record.
//
// Run it on a machine that is NOT the node. Everything the node needs is public and verifiable;
// the one thing it must never have is the key produced here. That asymmetry is the whole reason a
// self-certifying record system is worth anything: a node that cannot issue is a node whose
// compromise cannot mint addresses on your domain.
//
// The record it signs is not a blank one. It sets PolicyRequireCountersign and seeds the reserved
// local-part list, which together are what make the address gate real — an address on this domain
// is unusable until the root has attested it, and names like postmaster@ and countersign@ cannot
// be taken by whoever asks first.
func cmdDomainInit(args []string) error {
	fs := flag.NewFlagSet("domain init", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the domain to serve (e.g. mesh.example)")
	force := fs.Bool("force", false, "overwrite an existing root key for this domain")
	var seeds, bridges multiFlag
	fs.Var(&seeds, "seed", "a public seed multiaddr ending in /p2p/<peerID> (repeatable) — run `dmcnd peer-id` on the node for the peer ID")
	fs.Var(&bridges, "bridge", "a public multiaddr of a node running the SMTP bridge (repeatable). Usually the same address as --seed: it is what lets your users send to ordinary email")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	if *rf.passphrase == "" {
		return fmt.Errorf("--passphrase is required (or set DMCND_ROOT_PASSPHRASE) — it encrypts the root key at rest, and it is the only thing protecting your domain's trust anchor")
	}
	if len(seeds) == 0 {
		return fmt.Errorf("--seed is required: other domains find yours by dialling it.\n" +
			"  On the node, run `dmcnd peer-id`, then:\n" +
			"      --seed /ip4/<public-ip>/tcp/7400/p2p/<peer-id>\n" +
			"  Use the port the node actually listens on (DMCND_NODE_LISTEN) — this address is published\n" +
			"  in DNS and is not easy to change later.")
	}

	ks := keystore.New(*rf.keystore, *rf.passphrase)
	if existing, err := ks.Load(rootAlias(*domain)); err == nil && !*force {
		return fmt.Errorf("a root key for %s already exists in %s (fingerprint %s).\n"+
			"  Re-running would mint a DIFFERENT root, invalidating every record on the domain and the\n"+
			"  fp= you published. To hand the existing one to a node, use `domain publish`; to reprint\n"+
			"  the DNS record, `domain dns`.\n"+
			"  Pass --force only if you genuinely mean to start the domain over.",
			*domain, *rf.keystore, fingerprintOf(*domain, existing))
	}

	root, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}
	if err := ks.Store(rootAlias(*domain), root); err != nil {
		return fmt.Errorf("persist root key to %s: %w", *rf.keystore, err)
	}
	dar, err := buildDAR(*domain, root)
	if err != nil {
		return err
	}

	fmt.Println(dmcnTXT(*domain, dar.Fingerprint(), seeds, bridges))
	if len(bridges) == 0 {
		fmt.Fprintf(os.Stderr, "\nnote: no --bridge given, so your users cannot send to ordinary email addresses.\n"+
			"  Add the bridge's public multiaddr (usually the same as --seed) and re-run `domain dns`.\n")
	}
	fmt.Fprintf(os.Stderr, `
Root key: %s   (entry %s)

Next:
  1. Publish the TXT record above at your DNS provider.
  2. Start the node. It will report that it has no authority record yet and wait.
  3. Hand it this one — nothing secret leaves this machine, only the signed record:
       dmcndcli domain publish --domain %s --peers /ip4/<host>/tcp/7400/p2p/<peer-id>
  4. Back up %s somewhere offline. It is your domain's trust anchor: lose it and no address on
     %s can ever be issued or rotated again, and recovery means publishing a new fp= and having
     every correspondent re-verify you. Nobody can re-issue it for you.

The node cannot mint addresses. To give someone a mailbox, have them petition from the web UI and
run: dmcndcli petition assign --code <their code> --address <them>@%s
`, *rf.keystore, rootAlias(*domain), *domain, *rf.keystore, *domain, *domain)
	return nil
}

// cmdDomainPublish pushes the domain's authority record to a running node.
//
// This is the same libp2p record push `remove-address` uses, and it needs no credential: a
// self-hosted node accepts pushes for its own domain because relay.AcceptRecord — not the caller's
// identity — is what decides whether a record is legitimate. It checks the root-key continuity
// rule, so a node that already trusts a root will not silently accept a different one.
//
// Re-running it is safe and is how you roll the record forward after editing policy: the same
// revision must be byte-identical, and a higher one supersedes.
func cmdDomainPublish(args []string) error {
	fs := flag.NewFlagSet("domain publish", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the domain")
	peers := fs.String("peers", os.Getenv("DMCND_PEERS"), "comma-separated seed multiaddrs of the running daemon")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	if *peers == "" {
		return fmt.Errorf("--peers is required (or set DMCND_PEERS) — the running daemon to publish to.\n" +
			"  It looks like /ip4/<host>/tcp/7400/p2p/<peer-id>; the node prints its peer ID with `dmcnd peer-id`")
	}
	root, err := rf.load(*domain)
	if err != nil {
		return err
	}
	dar, err := buildDAR(*domain, root)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n, err := node.New(ctx, node.Config{
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		AllowedPeers: []string{"*"},
		ClientOnly:   true,
		Peers:        splitCSV(*peers),
	})
	if err != nil {
		return fmt.Errorf("start client node: %w", err)
	}
	defer n.Close()
	if err := n.WaitForPeers(ctx, 15*time.Second); err != nil {
		return fmt.Errorf("connect to the daemon: %w", err)
	}

	accepted, err := n.PublishDAR(ctx, dar)
	if err != nil {
		return fmt.Errorf("publish the authority record: %w", err)
	}
	fmt.Printf("published the authority record for %s (fp %s, accepted by %d node(s))\n", *domain, dar.Fingerprint(), accepted)
	fmt.Fprintln(os.Stderr, "the daemon should now report that it is serving the domain")
	return nil
}

// cmdDomainDNS reprints the _dmcn TXT record from the existing root. Mints nothing and touches no
// network, so it is always safe to run — for adding a seed address, or after moving the node.
func cmdDomainDNS(args []string) error {
	fs := flag.NewFlagSet("domain dns", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the domain")
	var seeds, bridges multiFlag
	fs.Var(&seeds, "seed", "a public seed multiaddr ending in /p2p/<peerID> (repeatable)")
	fs.Var(&bridges, "bridge", "a public multiaddr of a node running the SMTP bridge (repeatable)")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	root, err := rf.load(*domain)
	if err != nil {
		return err
	}
	dar, err := buildDAR(*domain, root)
	if err != nil {
		return err
	}
	fmt.Println(dmcnTXT(*domain, dar.Fingerprint(), seeds, bridges))
	if len(seeds) == 0 {
		fmt.Fprintf(os.Stderr, "\nnote: no --seed given, so nobody can dial you. Add your node's public multiaddr(s):\n"+
			"  dmcndcli domain dns --domain %s --seed /ip4/<public-ip>/tcp/7400/p2p/$(ssh node dmcnd peer-id)\n", *domain)
	}
	return nil
}

// buildDAR signs the domain authority record. The policy choices here are the gate: without
// RequireCountersign the reader-side check fails open and any self-signed record for the domain is
// usable, which would make the offline root ceremonial rather than load-bearing.
//
// It is deterministic given the root key, so init, publish and dns all produce the same record and
// the same fingerprint — that is what lets publish be re-run without minting anything.
func buildDAR(domain string, root *identity.IdentityKeyPair) (*identity.DomainAuthorityRecord, error) {
	dar, err := identity.NewDomainAuthorityRecord(domain, root, root.CreatedAt.UTC())
	if err != nil {
		return nil, fmt.Errorf("build the authority record: %w", err)
	}
	dar.PolicyFlags |= identity.PolicyRequireCountersign
	dar.ReservedLocalParts = append([]string(nil), identity.DefaultReservedLocalParts...)
	if err := dar.Sign(root); err != nil {
		return nil, fmt.Errorf("sign the authority record: %w", err)
	}
	return dar, nil
}

// dmcnTXT renders the _dmcn.<domain> TXT record: the v1 verification prefix, the root-key
// fingerprint (fp=), and one seed= token per bootstrap multiaddr.
func dmcnTXT(domain, fp string, seeds, bridges []string) string {
	val := "dmcn-verification=v1; fp=" + fp
	for _, s := range seeds {
		val += "; seed=" + s
	}
	for _, b := range bridges {
		val += "; bridge=" + b
	}
	return fmt.Sprintf("_dmcn.%s.  TXT  %q", domain, val)
}

func fingerprintOf(domain string, root *identity.IdentityKeyPair) string {
	dar, err := buildDAR(domain, root)
	if err != nil {
		return "unknown"
	}
	return dar.Fingerprint()
}
