package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// TestSPAEnvRendering locks in the shell's runtime-config plumbing: index.html is an
// html/template, so one embedded frontend build is configured per deployment by what the
// server renders into `env`. PETITION_MODE and DOMAIN_ROOT_PUB are the two that change
// behaviour — the first decides whether the register page creates a mailbox or asks for
// one, the second is what the client verifies a bridge credential against — so a silent
// rendering regression in either is a functional bug, not a cosmetic one.
func TestSPAEnvRendering(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": {Data: []byte(
			`DEFAULT_DOMAIN:'{{ .DefaultDomain }}';PETITION_MODE:'{{ .PetitionMode }}';DOMAIN_ROOT_PUB:'{{ .DomainRootPub }}'`)},
	}

	render := func(cfg FrontendConfig) string {
		h := spaHandler(fsys, cfg)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET / = %d, want 200", rec.Code)
		}
		return rec.Body.String()
	}

	// Live domain: the root key is offline, so the register page petitions rather than registers.
	body := render(FrontendConfig{
		DefaultDomain: "mesh.example",
		PetitionMode:  true,
		DomainRootPub: "dGVzdC1yb290LWtleQ==",
	})
	for _, want := range []string{
		"DEFAULT_DOMAIN:'mesh.example'",
		"PETITION_MODE:'true'",
		"DOMAIN_ROOT_PUB:'dGVzdC1yb290LWtleQ=='",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("shell missing %q in %q", want, body)
		}
	}

	// Unset: every value renders empty rather than as a literal template action, so the
	// frontend's own defaults apply.
	body = render(FrontendConfig{})
	for _, want := range []string{"DEFAULT_DOMAIN:''", "PETITION_MODE:''", "DOMAIN_ROOT_PUB:''"} {
		if !strings.Contains(body, want) {
			t.Errorf("shell missing %q in %q", want, body)
		}
	}
}
