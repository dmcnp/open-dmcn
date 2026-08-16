package webcore_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/webcore"
)

// --- Context ---

func TestAddressFromContext(t *testing.T) {
	ctx := context.WithValue(context.Background(), webcore.ContextKeyAddress, "alice@example.com")
	if got := webcore.AddressFromContext(ctx); got != "alice@example.com" {
		t.Fatalf("expected alice@example.com, got %q", got)
	}
}

func TestAddressFromContext_Missing(t *testing.T) {
	if got := webcore.AddressFromContext(context.Background()); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestAddressFromContext_WrongKeyType(t *testing.T) {
	// Using a plain string key should not match the typed contextKey.
	ctx := context.WithValue(context.Background(), "address", "alice@example.com") //nolint:staticcheck // deliberate plain-string key
	if got := webcore.AddressFromContext(ctx); got != "" {
		t.Fatalf("expected empty string for plain string key, got %q", got)
	}
}

// --- SessionStore ---

func testSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}

func TestSessionStore_CreateAndValidate(t *testing.T) {
	ss, err := webcore.NewSessionStore(testSecret(), time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	token, err := ss.Create("alice@dmcn.me")
	if err != nil {
		t.Fatal(err)
	}
	// A JWT has three base64url segments.
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected a JWT (header.payload.signature), got %q", token)
	}

	addr, err := ss.Validate(token)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "alice@dmcn.me" {
		t.Fatalf("expected alice@dmcn.me, got %q", addr)
	}
}

func TestSessionStore_ValidateExpired(t *testing.T) {
	// A negative TTL backdates exp (JWT exp is whole seconds), so the token is
	// already expired without a sleep.
	ss, _ := webcore.NewSessionStore(testSecret(), -time.Hour, "")
	token, _ := ss.Create("alice@dmcn.me")

	if _, err := ss.Validate(token); err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	ss, _ := webcore.NewSessionStore(testSecret(), time.Hour, "")
	token, _ := ss.Create("alice@dmcn.me")
	ss.Delete(token)

	if _, err := ss.Validate(token); err == nil {
		t.Fatal("expected error after revoke (logout)")
	}
}

func TestSessionStore_ValidateUnknown(t *testing.T) {
	ss, _ := webcore.NewSessionStore(testSecret(), time.Hour, "")
	if _, err := ss.Validate("nonexistenttoken"); err == nil {
		t.Fatal("expected error for malformed token")
	}
	// A token signed by a different secret must not verify (no shared state).
	other, _ := webcore.NewSessionStore([]byte("a-totally-different-32byte-secret"), time.Hour, "")
	tok, _ := other.Create("alice@dmcn.me")
	if _, err := ss.Validate(tok); err == nil {
		t.Fatal("expected error for a token signed by a different secret")
	}
}

func TestSessionStore_SurvivesRestartAndRevokePersists(t *testing.T) {
	secret := testSecret()
	revoked := filepath.Join(t.TempDir(), "revoked.json")

	s1, _ := webcore.NewSessionStore(secret, time.Hour, revoked)
	keep, _ := s1.Create("alice@dmcn.me")
	gone, _ := s1.Create("bob@dmcn.me")
	s1.Delete(gone) // revoke

	// A fresh store (same secret + denylist path) = a "restart": stateless tokens
	// still validate, and the revoked one stays revoked.
	s2, err := webcore.NewSessionStore(secret, time.Hour, revoked)
	if err != nil {
		t.Fatal(err)
	}
	if addr, err := s2.Validate(keep); err != nil || addr != "alice@dmcn.me" {
		t.Fatalf("token should survive restart: addr=%q err=%v", addr, err)
	}
	if _, err := s2.Validate(gone); err == nil {
		t.Fatal("revoked token must stay revoked across restart")
	}
}

// --- ChallengeStore ---

func TestChallengeStore_IssueGetDelete(t *testing.T) {
	cs := webcore.NewChallengeStore(time.Minute)
	nonce, err := cs.Issue("alice@dmcn.me")
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 32 {
		t.Fatalf("expected 32-byte nonce, got %d", len(nonce))
	}

	got, ok := cs.Get("alice@dmcn.me")
	if !ok || string(got) != string(nonce) {
		t.Fatalf("expected the issued nonce back, ok=%v", ok)
	}
	// Get does not consume — a failed signature attempt must leave it retryable.
	if _, ok := cs.Get("alice@dmcn.me"); !ok {
		t.Fatal("nonce should survive Get")
	}

	cs.Delete("alice@dmcn.me")
	if _, ok := cs.Get("alice@dmcn.me"); ok {
		t.Fatal("nonce should be gone after Delete")
	}
}

func TestChallengeStore_Expiry(t *testing.T) {
	cs := webcore.NewChallengeStore(-time.Second) // negative TTL is clamped to the default
	if _, err := cs.Issue("alice@dmcn.me"); err != nil {
		t.Fatal(err)
	}
	if _, ok := cs.Get("alice@dmcn.me"); !ok {
		t.Fatal("default-TTL nonce should be live")
	}

	fast := webcore.NewChallengeStore(time.Nanosecond)
	if _, err := fast.Issue("bob@dmcn.me"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, ok := fast.Get("bob@dmcn.me"); ok {
		t.Fatal("expired nonce must not be returned")
	}
}

func TestChallengeStore_IssueReplaces(t *testing.T) {
	cs := webcore.NewChallengeStore(time.Minute)
	first, _ := cs.Issue("alice@dmcn.me")
	second, _ := cs.Issue("alice@dmcn.me")
	got, ok := cs.Get("alice@dmcn.me")
	if !ok || string(got) == string(first) || string(got) != string(second) {
		t.Fatal("re-issue must replace the outstanding nonce")
	}
}
