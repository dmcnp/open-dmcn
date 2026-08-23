// Binary dmcndcli is the operator tool for a dmcnd deployment, and — on a live domain — the only
// thing that can issue anything.
//
// It is meant to run on a DIFFERENT machine from the node, ideally one that stays offline. The
// domain root key is created here and never leaves: the node is given a signed bundle of public
// material and has no way to mint an address on its own, so breaching the node does not get an
// attacker the ability to create or re-point mailboxes.
//
//	domain init      mint the domain root, sign its authority record, print the DNS record
//	domain publish   push that record to a running node (the only step that talks to the node)
//	domain dns       reprint the DNS record from the existing root
//	petition show    look up one mailbox petition by the code its petitioner gave you
//	petition assign  assign an address to a petitioned key, signing with the offline root
//	bridge issue     sign the credential that lets a node act as an SMTP bridge for the domain
//	bridge dkim-keygen
//	                 mint the outbound DKIM key and print the DNS records to publish
//	remove-address   root-sign a tombstone freeing an address, so it can be bound to a new key
//	peer-id          print the libp2p peer ID for an identity key
//
// The node's own `dmcnd peer-id` covers the peer ID on the node side; the copy here is for keys
// held on this machine.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/buildinfo"
	"dmcn.dev/open-dmcn/internal/node"
)

// version is stamped by the Makefile (-X main.version). A `go install` applies no ldflags, so
// buildinfo.Version falls back to the module version or the VCS revision.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println("dmcndcli", buildinfo.Version(version))
		return
	case "peer-id":
		err = cmdPeerID(os.Args[2:])
	case "domain":
		err = dispatchDomain(os.Args[2:])
	case "petition":
		err = dispatchPetition(os.Args[2:])
	case "bridge":
		err = dispatchBridge(os.Args[2:])
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

Run this on a machine that is NOT the node. It holds your domain's root key; the node never does.

Usage:
  dmcndcli domain init --domain <domain> --seed <multiaddr>... [--keystore root.enc]
        Mint the domain root key HERE and sign its authority record, then print the _dmcn TXT
        record to publish. Touches no network. Run 'dmcnd peer-id' on the node for the --seed
        multiaddr.

  dmcndcli domain publish --domain <domain> --peers <multiaddr>[,...]
        Push the signed authority record to a running daemon, which will not serve the domain
        until it has one. Sends only the public record — the root key stays here. Safe to re-run.

  dmcndcli domain dns --domain <domain> --seed <multiaddr>...
        Reprint the _dmcn TXT record from the existing root. Mints nothing, touches no network.

  dmcndcli petition show --domain <domain> --url <daemon-url> --code <12 digits>
        Look up one pending mailbox petition. By code only: there is no queue to browse, which is
        what keeps unwanted petitions from being work.

  dmcndcli petition assign --address <local@domain> --url <daemon-url> --code <12 digits>
        Give a petitioned key an address, signed with the offline root. The petitioner does not
        choose their address — you do. Their browser picks it up by itself.

  dmcndcli bridge issue --domain <domain> --peer <peerID> [--out bridge.cred]
        Sign the credential that lets a node act as an SMTP bridge for the domain. A bridge has
        no email address — recipients trust its SPF/DKIM/DMARC verdicts through this credential.
        Needs only the peer ID, so it runs offline: an Ed25519 peer ID contains its public key.

  dmcndcli bridge dkim-keygen --domain <email-domain> [--selector dmcn] [--out dkim.pem]
        Generate the DKIM signing key for outbound mail and print the SPF/DKIM/DMARC records to
        publish. Without DKIM, mail from a new host is filtered almost everywhere — and a key
        whose record is not published is worse still, since a failing signature beats none.

  dmcndcli remove-address --address <local@domain> --peers <multiaddr>[,...] [--pubkey <hex>] [--yes]
        Root-sign and publish a tombstone for an address's current key, freeing the address to be
        bound to a fresh one. This is the ONLY way to recover an address whose key was lost or
        compromised: the daemon refuses any record that re-binds a live address to a different key
        unless the domain root has tombstoned the incumbent.

  dmcndcli version
        Print this tool's version. It should match the daemon's — a credential or record format
        can move between releases.

  dmcndcli peer-id --identity <path>
        Print the libp2p peer ID for an identity key on THIS machine (created if missing). For the
        node's own peer ID, run 'dmcnd peer-id' there.

Commands that use the domain root key prompt for its passphrase when it is not supplied. For
scripted use prefer DMCND_ROOT_PASSPHRASE over --passphrase: a value in argv is readable via ps
by anyone else on the machine, and lands in shell history too.

Environment: DMCND_DOMAIN, DMCND_URL, DMCND_PEERS, DMCND_IDENTITY, DMCND_ROOT_KEYSTORE and
DMCND_ROOT_PASSPHRASE are used as defaults for the matching flags.
`)
}

// dispatchDomain routes the domain sub-commands.
func dispatchDomain(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("domain needs a sub-command: init, publish, dns")
	}
	switch args[0] {
	case "init":
		return cmdDomainInit(args[1:])
	case "publish":
		return cmdDomainPublish(args[1:])
	case "dns":
		return cmdDomainDNS(args[1:])
	default:
		return fmt.Errorf("unknown domain sub-command %q (want init, publish or dns)", args[0])
	}
}

// dispatchBridge routes the bridge sub-commands.
func dispatchBridge(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("bridge needs a sub-command: issue, dkim-keygen")
	}
	switch args[0] {
	case "issue":
		return cmdBridgeIssue(args[1:])
	case "dkim-keygen":
		return cmdDKIMKeygen(args[1:])
	default:
		return fmt.Errorf("unknown bridge sub-command %q (want issue or dkim-keygen)", args[0])
	}
}

// dispatchPetition routes the petition sub-commands.
func dispatchPetition(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("petition needs a sub-command: show, assign")
	}
	switch args[0] {
	case "show":
		return cmdPetitionShow(args[1:])
	case "assign":
		return cmdPetitionAssign(args[1:])
	default:
		return fmt.Errorf("unknown petition sub-command %q (want show or assign)", args[0])
	}
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
