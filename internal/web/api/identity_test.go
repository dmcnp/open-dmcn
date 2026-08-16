package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

func TestHandleRelayHints(t *testing.T) {
	expectedHints := []string{"/ip4/1.2.3.4/tcp/7400/p2p/QmTest1", "/ip4/5.6.7.8/tcp/7400/p2p/QmTest2"}

	h := api.NewIdentityHandler(
		func(ctx context.Context, address string) (*identity.IdentityRecord, error) {
			return nil, nil
		},
		nil,
		nil,
		func(ctx context.Context, address string) ([]string, error) { return expectedHints, nil },
		logr.With(logr.M("test", true)),
	)

	req := httptest.NewRequest("GET", "/api/v1/relay-hints?address=alice@example.com", nil)
	rr := httptest.NewRecorder()
	h.HandleRelayHints(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	hints, ok := resp["relay_hints"].([]interface{})
	if !ok {
		t.Fatal("expected relay_hints array")
	}
	if len(hints) != 2 {
		t.Fatalf("expected 2 hints, got %d", len(hints))
	}
	if hints[0].(string) != expectedHints[0] {
		t.Errorf("hint[0] = %q, want %q", hints[0], expectedHints[0])
	}
}

func TestHandleLookup_ReportsBridgeCapability(t *testing.T) {
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	rec := &identity.IdentityRecord{
		Address:          "bridge@bridge.localhost",
		Ed25519Public:    kp.Ed25519Public,
		X25519Public:     kp.X25519Public,
		VerificationTier: identity.TierDomainDNS,
		BridgeCapability: true,
	}
	h := api.NewIdentityHandler(
		func(context.Context, string) (*identity.IdentityRecord, error) { return rec, nil },
		nil,
		nil,
		func(context.Context, string) ([]string, error) { return nil, nil },
		logr.With(logr.M("test", true)),
	)

	req := httptest.NewRequest("GET", "/api/v1/identity/lookup?address=bridge@bridge.localhost", nil)
	rr := httptest.NewRecorder()
	h.HandleLookup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bc, ok := resp["bridge_capability"].(bool); !ok || !bc {
		t.Fatalf("bridge_capability = %v (ok=%v), want true", resp["bridge_capability"], ok)
	}
}

// A countersigned record reports the cryptographically verified tier; a record
// whose claimed countersignature fails verification is flagged unverifiable.
func TestHandleLookup_VerifiedTier(t *testing.T) {
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	signer, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// A record that actually carries an address credential so HasAddressCredential()
	// is true and verifyManaged is consulted.
	rec, err := identity.NewIdentityRecord("bridge@bridge.localhost", kp)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	rec.BridgeCapability = true
	if err := rec.Sign(kp); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := rec.IssueAddressCredential(signer, time.Now()); err != nil {
		t.Fatalf("issue address credential: %v", err)
	}

	lookup := func(context.Context, string) (*identity.IdentityRecord, error) { return rec, nil }

	t.Run("anchored", func(t *testing.T) {
		vm := func(context.Context, *identity.IdentityRecord) (identity.VerificationTier, error) {
			return identity.TierDomainDNS, nil
		}
		resp := doLookup(t, lookup, vm)
		if int(resp["verified_tier"].(float64)) != int(identity.TierDomainDNS) {
			t.Fatalf("verified_tier = %v, want %d", resp["verified_tier"], identity.TierDomainDNS)
		}
		if resp["identity_unverifiable"].(bool) {
			t.Fatal("anchored identity must not be flagged unverifiable")
		}
	})

	t.Run("revoked", func(t *testing.T) {
		vm := func(context.Context, *identity.IdentityRecord) (identity.VerificationTier, error) {
			return identity.TierUnverified, errors.New("registry: binding removed by domain")
		}
		resp := doLookup(t, lookup, vm)
		if int(resp["verified_tier"].(float64)) != int(identity.TierUnverified) {
			t.Fatalf("verified_tier = %v, want 0", resp["verified_tier"])
		}
		if !resp["identity_unverifiable"].(bool) {
			t.Fatal("a failed-countersignature identity must be flagged unverifiable")
		}
	})
}

func doLookup(t *testing.T, lookup func(context.Context, string) (*identity.IdentityRecord, error), vm func(context.Context, *identity.IdentityRecord) (identity.VerificationTier, error)) map[string]interface{} {
	t.Helper()
	h := api.NewIdentityHandler(lookup, vm, nil, func(context.Context, string) ([]string, error) { return nil, nil }, logr.With(logr.M("test", true)))
	req := httptest.NewRequest("GET", "/api/v1/identity/lookup?address=bridge@bridge.localhost", nil)
	rr := httptest.NewRecorder()
	h.HandleLookup(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// No mailbox relay for the domain ⇒ 503, so the client refuses to create a mailbox with
// no durable home (rather than embedding a placeholder hint).
func TestHandleRelayHints_Empty(t *testing.T) {
	h := api.NewIdentityHandler(
		func(ctx context.Context, address string) (*identity.IdentityRecord, error) {
			return nil, nil
		},
		nil,
		nil,
		func(ctx context.Context, address string) ([]string, error) { return nil, nil },
		logr.With(logr.M("test", true)),
	)

	req := httptest.NewRequest("GET", "/api/v1/relay-hints?address=alice@example.com", nil)
	rr := httptest.NewRecorder()
	h.HandleRelayHints(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rr.Code)
	}
}

// A missing address query parameter is a client error.
func TestHandleRelayHints_MissingAddress(t *testing.T) {
	h := api.NewIdentityHandler(
		func(ctx context.Context, address string) (*identity.IdentityRecord, error) { return nil, nil },
		nil,
		nil,
		func(ctx context.Context, address string) ([]string, error) {
			t.Fatal("placement should not be called without an address")
			return nil, nil
		},
		logr.With(logr.M("test", true)),
	)

	req := httptest.NewRequest("GET", "/api/v1/relay-hints", nil)
	rr := httptest.NewRecorder()
	h.HandleRelayHints(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}
