package main

import (
	"os"
	"testing"
)

// webhost_test.go covers separating the hostname the client is served on from the DMCN domain
// addresses belong to — mail at mail.example.com for user@example.com, the arrangement ordinary
// email has always had.

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
	// Anything not named must not leak in from the developer's shell.
	for _, k := range []string{"DMCND_DOMAIN", "DMCND_WEB_HOST", "DMCND_LISTEN", "DMCND_DEV"} {
		if _, named := kv[k]; !named {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
}

// TestWebHostDefaultsToTheDomain keeps every existing deployment working untouched: an operator
// who never heard of this variable gets exactly the previous behaviour.
func TestWebHostDefaultsToTheDomain(t *testing.T) {
	withEnv(t, map[string]string{"DMCND_DOMAIN": "merten.vg"})
	c := loadConfig()
	if c.webHost != "merten.vg" {
		t.Errorf("webHost = %q, want it to default to the domain", c.webHost)
	}
}

// TestWebHostCanBeASubdomain is the case this exists for.
func TestWebHostCanBeASubdomain(t *testing.T) {
	withEnv(t, map[string]string{"DMCND_DOMAIN": "merten.vg", "DMCND_WEB_HOST": "mail.merten.vg"})
	c := loadConfig()
	if c.domain != "merten.vg" {
		t.Errorf("domain = %q — addresses must still be @merten.vg", c.domain)
	}
	if c.webHost != "mail.merten.vg" {
		t.Errorf("webHost = %q, want mail.merten.vg", c.webHost)
	}
}

// TestWebHostDoesNotChangeAddresses is the property worth pinning: the SPA forms addresses from
// DefaultDomain, so if webHost ever leaked into it, everyone on the domain would silently be
// offered user@mail.merten.vg instead of user@merten.vg — and those addresses would not resolve,
// because the DAR and the _dmcn record are for the apex.
func TestWebHostDoesNotChangeAddresses(t *testing.T) {
	withEnv(t, map[string]string{"DMCND_DOMAIN": "merten.vg", "DMCND_WEB_HOST": "mail.merten.vg"})
	c := loadConfig()

	// These are the two fields the register/petition UI builds an address from.
	if c.domain != "merten.vg" {
		t.Fatalf("the DMCN domain moved to %q", c.domain)
	}
	// And the bridge's default SMTP domain follows the DMCN domain, not the web host: the MX
	// for merten.vg is what receives legacy mail.
	if c.bridgeDomain != "merten.vg" {
		t.Errorf("bridge domain = %q, want the DMCN domain", c.bridgeDomain)
	}
}
