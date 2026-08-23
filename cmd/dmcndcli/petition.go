package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
)

// petition.go is the admin half of mailbox provisioning on a live domain.
//
// Somebody asked you for a mailbox and read you twelve digits. That conversation is the
// authorization: there is no allowlist and no queue to triage, because a petition confers nothing
// until you act on a code you were given. These commands let you look one up and assign it an
// address, signing with the root key on this machine.
//
// Nothing about the petitioner's keys passes through here — they were generated in their browser
// and stay there. What you sign is an attestation ABOUT their public key: this key may use this
// address on my domain, and here is where its mail lives.

// petitionFlags are shared by show and assign.
type petitionFlags struct {
	domain   *string
	url      *string
	insecure *bool
	code     *string
	root     rootFlags
}

func addPetitionFlags(fs *flag.FlagSet) petitionFlags {
	return petitionFlags{
		domain:   fs.String("domain", os.Getenv("DMCND_DOMAIN"), "the domain (defaults from --address where given)"),
		url:      fs.String("url", os.Getenv("DMCND_URL"), "the daemon's webmail URL, e.g. https://mesh.example:8443"),
		insecure: fs.Bool("insecure", false, "skip TLS verification (self-signed dev certificates only)"),
		code:     fs.String("code", "", "the 12-digit code the petitioner gave you"),
		root:     addRootFlags(fs),
	}
}

// fetch runs the challenge-response and returns the petition the code names.
func (pf petitionFlags) fetch(domain string, root *identity.IdentityKeyPair) (*daemonClient, *petitionView, error) {
	c, err := newDaemonClient(*pf.url, *pf.insecure)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := c.challenge()
	if err != nil {
		return nil, nil, err
	}
	code := strings.TrimSpace(*pf.code)
	sig := ed25519.Sign(root.Ed25519Private, webapi.AdminSignableBytes(webapi.AdminGetContext, nonce, webapi.AdminGetBound(code)))

	var v petitionView
	err = c.postJSON("/api/v1/admin/petition/get", map[string]string{
		"code":      code,
		"nonce":     b64encode(nonce),
		"signature": b64encode(sig),
	}, &v)
	if err != nil {
		return nil, nil, err
	}
	return c, &v, nil
}

// petitionView is the daemon's answer for one code.
type petitionView struct {
	Code       string   `json:"code"`
	Ed25519Pub string   `json:"ed25519_pub"`
	X25519Pub  string   `json:"x25519_pub"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at"`
	Assigned   bool     `json:"assigned"`
	Address    string   `json:"address"`
	RelayHints []string `json:"relay_hints"`
	Domain     string   `json:"domain"`
}

// cmdPetitionShow prints one petition without changing anything, so an admin can confirm a code is
// real and unexpired before committing an address to it.
func cmdPetitionShow(args []string) error {
	fs := flag.NewFlagSet("petition show", flag.ExitOnError)
	pf := addPetitionFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pf.code == "" {
		return fmt.Errorf("--code is required")
	}
	if *pf.domain == "" {
		return fmt.Errorf("--domain is required (or set DMCND_DOMAIN)")
	}
	root, err := pf.root.load(*pf.domain)
	if err != nil {
		return err
	}
	_, v, err := pf.fetch(*pf.domain, root)
	if err != nil {
		return err
	}

	edPub, _ := b64decode(v.Ed25519Pub)
	fmt.Printf("code       %s\n", v.Code)
	fmt.Printf("key        %x\n", edPub)
	fmt.Printf("filed      %s\n", v.CreatedAt)
	fmt.Printf("expires    %s\n", v.ExpiresAt)
	if v.Assigned {
		fmt.Printf("assigned   %s (waiting for the petitioner to complete it)\n", v.Address)
	} else {
		fmt.Printf("assigned   no\n")
	}
	return nil
}

// cmdPetitionAssign binds an address to a petitioned key.
//
// This is the moment the domain root is used. It signs two attestations against the petitioner's
// PUBLIC key — an address credential (this key may use this address) and a routing credential
// (its mail lives on these relays) — and hands them to the node. The node parks them until the
// petitioner's browser returns with a self-signed record to attach them to, which it must, because
// a record's owner signature covers its address and the address did not exist until just now.
func cmdPetitionAssign(args []string) error {
	fs := flag.NewFlagSet("petition assign", flag.ExitOnError)
	address := fs.String("address", "", "the address to assign (local@domain)")
	pf := addPetitionFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pf.code == "" {
		return fmt.Errorf("--code is required — the 12 digits the petitioner gave you")
	}
	if *address == "" {
		return fmt.Errorf("--address is required: the petitioner does not choose their address, you do")
	}
	domain := *pf.domain
	if domain == "" {
		domain = domainverify.DomainOf(*address)
	}
	if domain == "" {
		return fmt.Errorf("invalid --address %q (want local@domain)", *address)
	}
	if d := domainverify.DomainOf(*address); !strings.EqualFold(d, domain) {
		return fmt.Errorf("--address is on %q but --domain is %q", d, domain)
	}

	root, err := pf.root.load(domain)
	if err != nil {
		return err
	}
	c, v, err := pf.fetch(domain, root)
	if err != nil {
		return err
	}
	if v.Assigned {
		return fmt.Errorf("petition %s was already assigned %s — a code is spent once, so if this is a new request ask for a fresh one", v.Code, v.Address)
	}
	if len(v.RelayHints) == 0 {
		return fmt.Errorf("the daemon reports no relay hints, so there is nowhere to route %s's mail", *address)
	}
	edPub, err := b64decode(v.Ed25519Pub)
	if err != nil || len(edPub) != ed25519.PublicKeySize {
		return fmt.Errorf("daemon returned an unusable ed25519 key for petition %s", v.Code)
	}
	xRaw, err := b64decode(v.X25519Pub)
	if err != nil || len(xRaw) != 32 {
		return fmt.Errorf("daemon returned an unusable x25519 key for petition %s", v.Code)
	}
	var xPub [32]byte
	copy(xPub[:], xRaw)

	// Build a record purely as a vehicle for issuing the two credentials against the petitioner's
	// keys. It is never published from here and never self-signed — only its owner can do that,
	// which is the point.
	now := time.Now().UTC()
	shell := &identity.IdentityRecord{
		Version:       1,
		Address:       *address,
		Ed25519Public: edPub,
		X25519Public:  xPub,
		CreatedAt:     now,
	}
	if err := shell.IssueAddressCredential(root, now); err != nil {
		return fmt.Errorf("issue address credential: %w", err)
	}
	if err := shell.IssueRoutingCredential(root, v.RelayHints, now); err != nil {
		return fmt.Errorf("issue routing credential: %w", err)
	}
	acPB, err := proto.Marshal(shell.AddressCredential.ToProto())
	if err != nil {
		return fmt.Errorf("encode address credential: %w", err)
	}
	rcPB, err := proto.Marshal(shell.RoutingCredential.ToProto())
	if err != nil {
		return fmt.Errorf("encode routing credential: %w", err)
	}

	nonce, err := c.challenge()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(root.Ed25519Private,
		webapi.AdminSignableBytes(webapi.AdminAssignContext, nonce, webapi.AdminAssignBound(strings.TrimSpace(*pf.code), *address)))

	var out struct {
		Status  string `json:"status"`
		Address string `json:"address"`
	}
	if err := c.postJSON("/api/v1/admin/petition/assign", map[string]string{
		"code":               strings.TrimSpace(*pf.code),
		"address":            *address,
		"address_credential": b64encode(acPB),
		"routing_credential": b64encode(rcPB),
		"nonce":              b64encode(nonce),
		"signature":          b64encode(sig),
	}, &out); err != nil {
		return err
	}

	fmt.Printf("assigned %s to petition %s\n", out.Address, *pf.code)
	fmt.Fprintf(os.Stderr, "The petitioner's browser will pick this up on its own — they do not need to be told the\n"+
		"address, only that it is ready. Their mailbox becomes live the moment they complete it.\n")
	return nil
}
