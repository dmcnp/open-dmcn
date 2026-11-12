package main

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// checkBridgeCredential refuses what recipients would refuse, so a credential copied from another
// domain (or issued to another node) stops the bridge at startup instead of failing in inboxes.
func TestCheckBridgeCredential(t *testing.T) {
	const domain = "bridge.test"
	now := time.Now()
	base := now.Add(-time.Hour).Truncate(time.Second)

	kp := func() *identity.IdentityKeyPair {
		k, err := identity.GenerateIdentityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	darFor := func(d string, root *identity.IdentityKeyPair) *identity.DomainAuthorityRecord {
		dar, err := identity.NewDomainAuthorityRecord(d, root, base)
		if err != nil {
			t.Fatal(err)
		}
		dar.AuthorityEffectiveFrom = base
		if err := dar.Sign(root); err != nil {
			t.Fatal(err)
		}
		return dar
	}
	issue := func(signer *identity.IdentityKeyPair, subject []byte, d string, roles ...string) *identity.Credential {
		c := &identity.Credential{Version: 1, Subject: subject, Domain: d, Roles: roles, IssuedAt: base}
		if err := c.Sign(signer); err != nil {
			t.Fatal(err)
		}
		return c
	}

	root, node := kp(), kp()
	dar := darFor(domain, root)
	cfg := config{domain: domain}

	good := issue(root, node.Ed25519Public, domain, identity.RoleBridge)
	if err := checkBridgeCredential(good, node.Ed25519Public, dar, nil, cfg, now); err != nil {
		t.Fatalf("a root-signed bridge credential for this node and domain must pass: %v", err)
	}

	otherRoot := kp()
	for name, tc := range map[string]struct {
		cred *identity.Credential
		want string
	}{
		"old domain's credential": {issue(otherRoot, node.Ed25519Public, "old.test", identity.RoleBridge), `domain "old.test"`},
		"another node's key":      {issue(root, kp().Ed25519Public, domain, identity.RoleBridge), "different node key"},
		"no bridge role":          {issue(root, node.Ed25519Public, domain, identity.RoleNode), "role"},
		"signed by another root":  {issue(otherRoot, node.Ed25519Public, domain, identity.RoleBridge), "does not verify"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkBridgeCredential(tc.cred, node.Ed25519Public, dar, nil, cfg, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error mentioning %q, got %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "dmcndcli bridge issue --domain "+domain) {
				t.Fatalf("the error should name the command that fixes it: %v", err)
			}
		})
	}
}

// The bridge's STARTTLS hands autocert a name it has a certificate for even when the sending MTA
// sends no SNI (common) or an unrelated one — autocert refuses both, which would push every such
// sender back to cleartext.
func TestBridgeSMTPTLSServerName(t *testing.T) {
	var asked string
	get := func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		asked = h.ServerName
		return &tls.Certificate{}, nil
	}
	tc := bridgeSMTPTLS(get, []string{"mail.bridge.test", "bridge.test"}, "mail.bridge.test")
	if len(tc.NextProtos) != 0 {
		t.Fatalf("SMTP TLS must not offer ALPN (acme-tls/1 belongs on :443): %v", tc.NextProtos)
	}
	for sni, want := range map[string]string{
		"":                  "mail.bridge.test",
		"mx.elsewhere.test": "mail.bridge.test",
		"MAIL.bridge.test.": "MAIL.bridge.test.", // known name: passed through, autocert normalises it
		"bridge.test":       "bridge.test",
	} {
		hello := &tls.ClientHelloInfo{ServerName: sni}
		if _, err := tc.GetCertificate(hello); err != nil {
			t.Fatal(err)
		}
		if asked != want {
			t.Errorf("SNI %q: asked autocert for %q, want %q", sni, asked, want)
		}
		if hello.ServerName != sni {
			t.Errorf("the caller's hello must not be modified (%q became %q)", sni, hello.ServerName)
		}
	}
}

func TestBridgeOffReason(t *testing.T) {
	for name, tc := range map[string]struct {
		env  []string
		want string // "" = no warning
	}{
		"not configured":         {[]string{"DMCND_DOMAIN=x.test"}, ""},
		"explicitly off":         {[]string{"DMCND_BRIDGE_ENABLED=false", "DMCND_BRIDGE_CREDENTIAL=/c"}, ""},
		"enabled line missing":   {[]string{"DMCND_BRIDGE_CREDENTIAL=/c", "DMCND_BRIDGE_DKIM_KEY=/k"}, "DMCND_BRIDGE_CREDENTIAL, DMCND_BRIDGE_DKIM_KEY set"},
		"yes is not true":        {[]string{"DMCND_BRIDGE_ENABLED=yes"}, `"yes" is not read as true`},
		"trailing comment kept":  {[]string{"DMCND_BRIDGE_ENABLED=true # smtp"}, `"true # smtp"`},
		"empty values are unset": {[]string{"DMCND_BRIDGE_CREDENTIAL="}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := bridgeOffReason(tc.env)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
