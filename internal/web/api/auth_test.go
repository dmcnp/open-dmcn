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

	"dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/registry"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// newTestAuthHandler builds an AuthHandler whose directory is the given DHT
// record set — the client keeps no user store; the DHT registry IS the directory.
func newTestAuthHandler(t *testing.T, records map[string]*identity.IdentityRecord) (*api.AuthHandler, *webcore.SessionStore) {
	t.Helper()
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if rec, ok := records[addr]; ok {
			return rec, nil
		}
		return nil, registry.ErrNotFound
	}
	return api.NewAuthHandler(ss, lookup, logr.With(logr.M("test", true))), ss
}

func createSignedIdentityRecord(t *testing.T, address string) (*identity.IdentityKeyPair, *identity.IdentityRecord, []byte) {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	pb := rec.ToProto()
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	return kp, rec, data
}

// loginChallenge runs the login step and returns the response fields.
func loginChallenge(t *testing.T, h *api.AuthHandler, address string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/login", strings.NewReader(`{"address":"`+address+`"}`))
	rr := httptest.NewRecorder()
	h.HandleLogin(rr, req)
	return rr
}

func postLoginVerify(t *testing.T, h *api.AuthHandler, address, nonceB64, sigB64 string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"address":             address,
		"challenge_signature": sigB64,
		"challenge_nonce":     nonceB64,
	})
	req := httptest.NewRequest("POST", "/api/v1/login/verify", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	h.HandleLoginVerify(rr, req)
	return rr
}

// The full DHT-verified login round-trip: the address needs only a DHT record —
// no prior import/registration on this client instance (that's the point of
// dropping the local directory).
func TestHandleLogin_AndVerify(t *testing.T) {
	kp, rec, _ := createSignedIdentityRecord(t, "bob@dmcn.me")
	h, ss := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"bob@dmcn.me": rec})

	rr := loginChallenge(t, h, "bob@dmcn.me")
	if rr.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var loginResp map[string]string
	json.NewDecoder(rr.Body).Decode(&loginResp)
	if loginResp["ed25519_pub"] != base64.StdEncoding.EncodeToString(kp.Ed25519Public) {
		t.Fatal("login must return the DHT record's public key")
	}
	nonce, err := base64.StdEncoding.DecodeString(loginResp["challenge_nonce"])
	if err != nil || len(nonce) == 0 {
		t.Fatalf("bad challenge nonce: %v", err)
	}

	sig, err := crypto.Sign(kp.Ed25519Private, nonce)
	if err != nil {
		t.Fatal(err)
	}
	rr2 := postLoginVerify(t, h, "bob@dmcn.me", loginResp["challenge_nonce"], base64.StdEncoding.EncodeToString(sig))
	if rr2.Code != http.StatusOK {
		t.Fatalf("verify: expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var verifyResp map[string]string
	json.NewDecoder(rr2.Body).Decode(&verifyResp)
	if verifyResp["session_token"] == "" {
		t.Fatal("expected session_token in verify response")
	}
	if addr, err := ss.Validate(verifyResp["session_token"]); err != nil || addr != "bob@dmcn.me" {
		t.Fatalf("session must validate to the address: %q %v", addr, err)
	}
}

func TestHandleLogin_UnknownAddress(t *testing.T) {
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{})
	if rr := loginChallenge(t, h, "ghost@dmcn.me"); rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an address with no DHT record, got %d", rr.Code)
	}
}

func TestHandleLoginVerify_BadSignature(t *testing.T) {
	_, rec, _ := createSignedIdentityRecord(t, "carol@dmcn.me")
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"carol@dmcn.me": rec})

	rr := loginChallenge(t, h, "carol@dmcn.me")
	var loginResp map[string]string
	json.NewDecoder(rr.Body).Decode(&loginResp)

	rr2 := postLoginVerify(t, h, "carol@dmcn.me", loginResp["challenge_nonce"], base64.StdEncoding.EncodeToString(make([]byte, 64)))
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rr2.Code, rr2.Body.String())
	}
}

func TestHandleLoginVerify_NoPendingChallenge(t *testing.T) {
	_, rec, _ := createSignedIdentityRecord(t, "carol@dmcn.me")
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"carol@dmcn.me": rec})

	rr := postLoginVerify(t, h, "carol@dmcn.me", base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(make([]byte, 64)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a pending challenge, got %d", rr.Code)
	}
}

// --- Import (possession-proof onboarding of keys that arrived out-of-band) ---

// importChallengeNonce runs the import-challenge step and returns the nonce (b64).
func importChallengeNonce(t *testing.T, h *api.AuthHandler, address string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/import/challenge", strings.NewReader(`{"address":"`+address+`"}`))
	rr := httptest.NewRecorder()
	h.HandleImportChallenge(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("import challenge: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	return resp["challenge_nonce"]
}

func postImport(t *testing.T, h *api.AuthHandler, body map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/import", strings.NewReader(string(b)))
	rr := httptest.NewRecorder()
	h.HandleImport(rr, req)
	return rr
}

func TestHandleImport_Success(t *testing.T) {
	kp, rec, _ := createSignedIdentityRecord(t, "alice@dmcn.me")
	h, ss := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"alice@dmcn.me": rec})

	nonceB64 := importChallengeNonce(t, h, "alice@dmcn.me")
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	sig, err := crypto.Sign(kp.Ed25519Private, nonce)
	if err != nil {
		t.Fatal(err)
	}

	rr := postImport(t, h, map[string]interface{}{
		"address":             "alice@dmcn.me",
		"challenge_nonce":     nonceB64,
		"challenge_signature": base64.StdEncoding.EncodeToString(sig),
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["session_token"] == "" {
		t.Fatal("expected session_token")
	}
	if addr, err := ss.Validate(resp["session_token"]); err != nil || addr != "alice@dmcn.me" {
		t.Fatalf("session must validate to the address: %q %v", addr, err)
	}
}

func TestHandleImport_WrongKeyRejected(t *testing.T) {
	_, rec, _ := createSignedIdentityRecord(t, "alice@dmcn.me")
	attacker, _, _ := createSignedIdentityRecord(t, "mallory@dmcn.me")
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"alice@dmcn.me": rec})

	nonceB64 := importChallengeNonce(t, h, "alice@dmcn.me")
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	// Sign with the wrong (attacker's) key.
	sig, _ := crypto.Sign(attacker.Ed25519Private, nonce)

	rr := postImport(t, h, map[string]interface{}{
		"address":             "alice@dmcn.me",
		"challenge_nonce":     nonceB64,
		"challenge_signature": base64.StdEncoding.EncodeToString(sig),
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a mismatched key, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleImport_UnregisteredAddress(t *testing.T) {
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{})

	req := httptest.NewRequest("POST", "/api/v1/import/challenge", strings.NewReader(`{"address":"ghost@dmcn.me"}`))
	rr := httptest.NewRecorder()
	h.HandleImportChallenge(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for an unregistered address, got %d", rr.Code)
	}
}

func TestHandleImport_NoPendingChallenge(t *testing.T) {
	_, rec, _ := createSignedIdentityRecord(t, "alice@dmcn.me")
	h, _ := newTestAuthHandler(t, map[string]*identity.IdentityRecord{"alice@dmcn.me": rec})

	rr := postImport(t, h, map[string]interface{}{
		"address":             "alice@dmcn.me",
		"challenge_nonce":     base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"challenge_signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a pending challenge, got %d", rr.Code)
	}
}
