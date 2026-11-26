package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/pairing"
	"dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// pairRecordB64 builds a signed record that expires at the given moment (the zero time for a
// record that never does), as a browser would submit it.
func pairRecordB64(t *testing.T, address string, expires time.Time) string {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		t.Fatal(err)
	}
	rec.ExpiresAt = expires
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(rec.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// An open endpoint that stores whatever lifetime it is handed is a place to park records for
// good. A pairing record lives for the pairing window and no longer.
func TestPairRegisterBoundsTheRecordLifetime(t *testing.T) {
	now := time.Now()
	for name, expires := range map[string]time.Time{
		"never expires":      {},
		"expires in a year":  now.Add(365 * 24 * time.Hour),
		"expires in an hour": now.Add(time.Hour),
		"already expired":    now.Add(-time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			h, published := newPairHandlerCounting(t)
			rr := postPair(h.HandleRegister, `{"identity_record":"`+pairRecordB64(t, "pair-0011223344556677@pairing.local", expires)+`"}`)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400: %s", rr.Code, rr.Body.String())
			}
			if *published != 0 {
				t.Fatal("a record with an unusable lifetime was published")
			}
		})
	}

	// A device whose clock runs ten minutes fast still pairs.
	h, published := newPairHandlerCounting(t)
	fast := now.Add(10*time.Minute + pairing.EphemeralTTL)
	if rr := postPair(h.HandleRegister, `{"identity_record":"`+pairRecordB64(t, "pair-0011223344556677@pairing.local", fast)+`"}`); rr.Code != http.StatusNoContent {
		t.Fatalf("got %d, want 204: %s", rr.Code, rr.Body.String())
	}
	if *published != 1 {
		t.Fatal("a usable pairing record was not published")
	}
}

// The pairing session is given to anyone who names a pairing address, so it ends with the
// pairing window and not with an ordinary sign-in.
func TestPairSessionEndsWithThePairingWindow(t *testing.T) {
	h, _ := newPairHandlerCounting(t)
	rr := postPair(h.HandleSession, `{"ephemeral_address":"pair-0011223344556677@pairing.local"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(resp["session_token"], ".")
	if len(parts) != 3 {
		t.Fatalf("not a signed token: %q", resp["session_token"])
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if left := time.Until(time.Unix(claims.Exp, 0)); left > pairing.EphemeralTTL || left < pairing.EphemeralTTL-time.Minute {
		t.Fatalf("the session lasts %v, want the pairing window of %v", left, pairing.EphemeralTTL)
	}
}

// newPairHandlerCounting returns a handler over a 24-hour session store, and a count of the
// records it published.
func newPairHandlerCounting(t *testing.T) (*api.PairHandler, *int) {
	t.Helper()
	ss, err := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), 24*time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	published := 0
	return api.NewPairHandler(ss, func(context.Context, *identity.IdentityRecord) error {
		published++
		return nil
	}, logr.With(logr.M("test", true))), &published
}

func postPair(handle http.HandlerFunc, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handle(rr, httptest.NewRequest("POST", "/", strings.NewReader(body)))
	return rr
}
