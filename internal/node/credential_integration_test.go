package node_test

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// credNode starts a credential-mode node: it loads/creates a libp2p identity key, issues
// it a Credential signed by the domain root (Subject == its own peer key, unless
// subjectOverride is set for a rejection test), and runs with that credential + the
// domain DAR. No AllowedPeers — federation is credential-gated.
func credNode(t *testing.T, ctx context.Context, domain string, root *identity.IdentityKeyPair, dar *identity.DomainAuthorityRecord, roles []string, subjectOverride ed25519.PublicKey) *node.Node {
	return credNodeBoot(t, ctx, domain, root, dar, roles, subjectOverride, nil)
}

func credNodeBoot(t *testing.T, ctx context.Context, domain string, root *identity.IdentityKeyPair, dar *identity.DomainAuthorityRecord, roles []string, subjectOverride ed25519.PublicKey, bootstrap []string) *node.Node {
	t.Helper()
	keyfile := filepath.Join(t.TempDir(), "id.key")
	priv, err := node.LoadOrCreateIdentityKey(keyfile)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := priv.GetPublic().Raw()
	if err != nil {
		t.Fatal(err)
	}
	subject := ed25519.PublicKey(raw)
	if subjectOverride != nil {
		subject = subjectOverride
	}
	cred := &identity.Credential{
		Version:    1,
		Subject:    subject,
		Domain:     domain,
		Roles:      roles,
		IssuedAt:   time.Now(),
		Attributes: map[string]string{"ip": "127.0.0.1"},
	}
	if err := cred.Sign(root); err != nil {
		t.Fatal(err)
	}
	n, err := node.New(ctx, node.Config{
		ListenAddr:      "/ip4/127.0.0.1/tcp/0",
		IdentityKeyPath: keyfile,
		Credential:      cred,
		CredentialDAR:   dar,
		Peers:  bootstrap,
		DNSVerifier:     okDNS,
	})
	if err != nil {
		t.Fatalf("cred node: %v", err)
	}
	return n
}

// TestCredentialJoinGatesFederation proves S2: two credential-mode nodes mutually admit
// each other over /dmcn/join (no peer-ID allowlist), and a node presenting a credential
// whose Subject is NOT its own peer key is rejected.
func TestCredentialJoinGatesFederation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const domain = "creds.test"
	root, _ := identity.GenerateIdentityKeyPair()
	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.AuthorityEffectiveFrom = time.Now().Add(-time.Hour)
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	a := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, nil)
	defer a.Close()
	b := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, nil)
	defer b.Close()

	if err := a.ConnectPeer(b.RelayHints()[0]); err != nil {
		t.Fatalf("connect a→b: %v", err)
	}

	// The mutual join completes asynchronously after the connection.
	if !eventually(t, 15*time.Second, func() bool { return a.Admitted(b.PeerID()) && b.Admitted(a.PeerID()) }) {
		t.Fatalf("nodes did not mutually admit via /dmcn/join (a→b %t, b→a %t)", a.Admitted(b.PeerID()), b.Admitted(a.PeerID()))
	}

	// A node whose credential Subject != its own peer key must be rejected.
	wrong, _ := identity.GenerateIdentityKeyPair()
	c := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, wrong.Ed25519Public)
	defer c.Close()
	if err := c.ConnectPeer(a.RelayHints()[0]); err != nil {
		t.Fatalf("connect c→a: %v", err)
	}
	time.Sleep(3 * time.Second)
	if a.Admitted(c.PeerID()) {
		t.Fatal("a credential whose Subject does not match the peer id must NOT be admitted")
	}
}

func eventually(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return cond()
}
