package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// cmdRemoveAddress publishes a root-signed AddressRemovalRecord tombstoning an address's current
// key, freeing the address to be bound to a new one.
//
// This is the counterpart to the key-continuity rule the daemon enforces on every record write: a
// record whose owner key differs from the one already stored is refused unless a root-signed
// tombstone for the incumbent key exists. That rule is what stops anyone who can push a record from
// silently re-binding a live address to their own key — but it also means an address whose key is
// lost, compromised or squatted CANNOT be recovered without this ceremony. Hence root-only, and
// hence it lives in the operator CLI rather than the web UI — on the machine holding the root key,
// which is not the node.
//
// Ordering matters and is deliberate: the tombstone is published FIRST, so the old key is dead even
// if the operator never gets around to re-binding the address. The address is then re-bound the
// same way any address is: the new holder petitions from the web UI and you assign it to them.
func cmdRemoveAddress(args []string) error {
	fs := flag.NewFlagSet("remove-address", flag.ExitOnError)
	address := fs.String("address", "", "the address to free (local@domain)")
	peers := fs.String("peers", os.Getenv("DMCND_PEERS"), "comma-separated seed multiaddrs of the running daemon")
	pubkeyHex := fs.String("pubkey", "", "hex Ed25519 key to tombstone (default: the address's currently published key)")
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	rf := addRootFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *address == "" {
		return fmt.Errorf("--address is required")
	}
	domain := domainverify.DomainOf(*address)
	if domain == "" {
		return fmt.Errorf("invalid --address %q (want local@domain)", *address)
	}
	if *peers == "" {
		return fmt.Errorf("--peers is required (or set DMCND_PEERS) — the running daemon to publish through")
	}

	root, err := rf.load(domain)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	n, err := dialDaemon(ctx, *peers)
	if err != nil {
		return err
	}
	defer n.Close()

	// Pick the victim key: an explicit --pubkey (for a squatted address whose record you do not
	// want to trust) or whatever is currently published.
	var victim []byte
	if *pubkeyHex != "" {
		if victim, err = hex.DecodeString(strings.TrimSpace(*pubkeyHex)); err != nil {
			return fmt.Errorf("parse --pubkey: %w", err)
		}
	} else {
		cur, lerr := n.Registry().Lookup(ctx, *address)
		if lerr != nil {
			return fmt.Errorf("look up %s (pass --pubkey to tombstone a specific key): %w", *address, lerr)
		}
		victim = cur.Ed25519Public
	}

	if !*yes {
		fmt.Fprintf(os.Stderr, "This tombstones key %s for %s.\nThe key is permanently dead: every device holding it loses access, and stored mail does not migrate.\nContinue? [y/N] ", hex.EncodeToString(victim), *address)
		var answer string
		fmt.Scanln(&answer)
		if !strings.EqualFold(strings.TrimSpace(answer), "y") {
			return fmt.Errorf("aborted")
		}
	}

	dar, err := n.Registry().LookupDomainAuthority(ctx, domain)
	if err != nil {
		return fmt.Errorf("look up the domain authority for %s: %w", domain, err)
	}
	// Rebuild from a verified union across the fleet rather than re-signing a record fetched from
	// one peer: signing an unverified blob with the domain root would turn this ceremony into a
	// signature oracle for whatever a hostile peer chose to return.
	rm, uerr := n.FetchRemovalUnion(ctx, dar, *address)
	if uerr != nil {
		if rm, err = identity.NewAddressRemovalRecord(domain, *address, time.Now().UTC()); err != nil {
			return err
		}
	} else {
		if _, already := rm.Removed(victim); already {
			fmt.Printf("%s is already tombstoned for %s (revision %d) — nothing to do\n", hex.EncodeToString(victim), *address, rm.Revision)
			return nil
		}
		rm.Revision++
		rm.CreatedAt = time.Now().UTC()
	}
	rm.RemovedBindings = append(rm.RemovedBindings, identity.RemovedBinding{
		Ed25519Public: victim,
		RemovedAt:     time.Now().UTC(),
	})
	if err := rm.Sign(root); err != nil {
		return fmt.Errorf("sign removal record: %w", err)
	}
	accepted, err := n.PublishRemoval(ctx, rm)
	if err != nil {
		return fmt.Errorf("publish removal record: %w", err)
	}
	fmt.Printf("tombstoned %s for %s (revision %d, accepted by %d node(s))\n", hex.EncodeToString(victim), *address, rm.Revision, accepted)
	fmt.Println("the address is now free. To re-bind it, have the new holder petition from the web UI\nand run: dmcndcli petition assign --code <their code> --address " + *address)
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
