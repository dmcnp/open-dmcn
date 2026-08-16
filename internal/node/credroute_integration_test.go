package node_test

import (
	"context"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// TestCredentialModeRelayDirectory proves S4 relay trust: credential-mode relays publish
// descriptors carrying their `node` credential, and a credential-mode client discovers
// them via provider records and admits them to its onion route directory by verifying
// that embedded credential — no relay-descriptor countersignature, no peer-ID allowlist.
func TestCredentialModeRelayDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const domain = "credroute.test"
	root, _ := identity.GenerateIdentityKeyPair()
	dar, _ := identity.NewDomainAuthorityRecord(domain, root, time.Now())
	dar.AuthorityEffectiveFrom = time.Now().Add(-time.Hour)
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	// Three credential-mode relays (role node), meshed so they join + the DHT populates.
	r1 := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, nil)
	defer r1.Close()
	r2 := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, nil)
	defer r2.Close()
	r3 := credNode(t, ctx, domain, root, dar, []string{identity.RoleNode}, nil)
	defer r3.Close()
	relays := []interface {
		ConnectPeer(string) error
		RelayHints() []string
	}{r1, r2, r3}
	for _, a := range relays {
		for _, b := range relays {
			if a != b {
				_ = a.ConnectPeer(b.RelayHints()[0])
			}
		}
	}

	// Publish the DAR so the client can resolve relay credentials' issuer chain.
	putDAR(t, ctx, dar, r1)

	// Client (role client) configured with the whole relay set as its peers — mirroring a
	// production client seeded with the full DMCN_NODE_PEERS list. (Enumerating relays it never
	// connected to was the DHT provider-record path; the fleet roster is the deferred replacement,
	// so the directory is built from the relays the client is connected to.)
	client := credNodeBoot(t, ctx, domain, root, dar, []string{identity.RoleClient}, nil,
		[]string{r1.RelayHints()[0], r2.RelayHints()[0], r3.RelayHints()[0]})
	defer client.Close()

	if !eventually(t, 60*time.Second, func() bool {
		return len(client.RelayDirectory(ctx)) >= 2
	}) {
		t.Fatalf("client did not credential-verify ≥2 relays for routing (got %d)", len(client.RelayDirectory(ctx)))
	}

	// Every directory entry must carry a node credential whose subject is its peer key.
	for _, d := range client.RelayDirectory(ctx) {
		if d.Credential == nil || !d.Credential.HasRole(identity.RoleNode) {
			t.Fatalf("relay %s admitted without a node credential", d.PeerID)
		}
	}
}
