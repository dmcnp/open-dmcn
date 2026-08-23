package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dmcn.dev/open-dmcn/internal/web/api"
)

// routeSet wires RegisterAPI the way the daemon does for one mode and reports which paths exist.
// The API handlers are nil: RegisterAPI only takes method values off them, and these tests never
// invoke a handler — they ask the mux whether a route is there at all.
func routeSet(t *testing.T, reg *api.RegisterHandler, pet *api.PetitionHandler) func(method, path string) int {
	t.Helper()
	s := &Server{mux: http.NewServeMux()}
	s.RegisterAPI(nil, nil, nil, nil, reg, pet,
		func(h http.HandlerFunc) http.HandlerFunc { return h }, nil, FrontendConfig{})
	return func(method, path string) int {
		_, pattern := s.mux.Handler(httptest.NewRequest(method, path, nil))
		if pattern == "" {
			return http.StatusNotFound
		}
		return http.StatusOK
	}
}

// TestLiveDomainHasNoRegisterRoute is the structural half of moving the root offline. A live daemon
// holds no key that could sign an address credential, so self-service registration must not merely
// fail — the route must not exist. A disabled-but-present handler is one refactor away from being
// re-enabled by accident; an absent route cannot be.
func TestLiveDomainHasNoRegisterRoute(t *testing.T) {
	has := routeSet(t, nil, &api.PetitionHandler{})

	if has("POST", "/api/v1/register") != http.StatusNotFound {
		t.Error("/api/v1/register is routed on a live domain — the daemon has no root key to provision with")
	}
	for _, p := range []string{
		"/api/v1/petition",
		"/api/v1/petition/complete",
		"/api/v1/admin/challenge",
		"/api/v1/admin/petition/get",
		"/api/v1/admin/petition/assign",
	} {
		if has("POST", p) != http.StatusOK {
			t.Errorf("%s is not routed on a live domain", p)
		}
	}
	if has("GET", "/api/v1/petition/status") != http.StatusOK {
		t.Error("/api/v1/petition/status is not routed on a live domain")
	}
}

// TestDevDomainHasNoPetitionRoutes is the converse: dev mode holds the root and registers on
// demand, so there is no queue and nothing for an admin endpoint to open.
func TestDevDomainHasNoPetitionRoutes(t *testing.T) {
	has := routeSet(t, &api.RegisterHandler{}, nil)

	if has("POST", "/api/v1/register") != http.StatusOK {
		t.Error("/api/v1/register is not routed in dev mode")
	}
	for _, p := range []string{"/api/v1/petition", "/api/v1/admin/petition/get", "/api/v1/admin/challenge"} {
		if has("POST", p) != http.StatusNotFound {
			t.Errorf("%s is routed in dev mode, where there is no petition queue", p)
		}
	}
}
