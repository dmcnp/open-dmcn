package api_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// fakeRelayRouter records which delivery path HandleSend took (direct STORE vs onion).
type fakeRelayRouter struct {
	storeCalls int
	onionCalls int
	// lastHints records the relay hints a STORE was routed to, so a test can assert WHERE mail
	// went and not merely that it went somewhere.
	lastHints []string
}

func (f *fakeRelayRouter) ConnectPeer(string) error { return nil }

func (f *fakeRelayRouter) StorePreSignedOnPeer(_ context.Context, hint, _ string, _ []byte, _ *message.EncryptedEnvelope) ([32]byte, error) {
	f.storeCalls++
	f.lastHints = append(f.lastHints, hint)
	return [32]byte{}, nil
}

func (f *fakeRelayRouter) SendOnionPreSigned(_ context.Context, _ string, _ []byte, _ *identity.IdentityRecord, _ *message.EncryptedEnvelope) ([32]byte, error) {
	f.onionCalls++
	return [32]byte{}, nil
}

// validEnvelopeB64 builds a real split envelope and returns it base64-encoded, for
// send tests that need the handler to get past envelope decoding.
func validEnvelopeB64(t *testing.T) string {
	t.Helper()
	senderKP, _ := identity.GenerateIdentityKeyPair()
	recipientKP, _ := identity.GenerateIdentityKeyPair()
	msg, _ := message.NewPlaintextMessage("alice@dmcn.me", "bob@dmcn.me", "s", "b", senderKP.Ed25519Public)
	sh, content, err := message.Split(msg, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	env, err := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: recipientKP.X25519Public}}, senderKP.Ed25519Private)
	if err != nil {
		t.Fatal(err)
	}
	b, err := proto.Marshal(env.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// sendsViaOnion drives HandleSend with a valid envelope and a recipient that has
// relay hints, and reports which delivery path the router took.
func sendsViaOnion(t *testing.T, reqOnion, recipientRequireOnion bool) *fakeRelayRouter {
	t.Helper()
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return &identity.IdentityRecord{
			Address:      addr,
			RelayHints:   []string{"/ip4/127.0.0.1/tcp/1"},
			RequireOnion: recipientRequireOnion,
		}, nil
	}
	router := &fakeRelayRouter{}
	h := api.NewMessageHandler(nil, lookup, router, nil, nil, logr.With(logr.M("test", true)))

	body := fmt.Sprintf(`{"sender_address":"alice@dmcn.me","sender_signature":"AAAA","envelope":%q,"recipient_address":"bob@dmcn.me","onion":%t}`, validEnvelopeB64(t), reqOnion)
	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", body, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	return router
}

func TestHandleSend_OnionWhenRequested(t *testing.T) {
	r := sendsViaOnion(t, true, false)
	if r.onionCalls != 1 || r.storeCalls != 0 {
		t.Fatalf("onion requested: onionCalls=%d storeCalls=%d, want 1/0", r.onionCalls, r.storeCalls)
	}
}

func TestHandleSend_OnionForcedByRecipient(t *testing.T) {
	r := sendsViaOnion(t, false, true)
	if r.onionCalls != 1 || r.storeCalls != 0 {
		t.Fatalf("recipient RequireOnion: onionCalls=%d storeCalls=%d, want 1/0", r.onionCalls, r.storeCalls)
	}
}

func TestHandleSend_DirectWhenNotRequested(t *testing.T) {
	r := sendsViaOnion(t, false, false)
	if r.storeCalls != 1 || r.onionCalls != 0 {
		t.Fatalf("plain send: storeCalls=%d onionCalls=%d, want 1/0", r.storeCalls, r.onionCalls)
	}
}

// A recipient whose routing credential can't be verified (forged/absent on a managed domain)
// must NOT receive mail — the send is rejected and no relay is contacted, defeating the
// forged-routing redirection attack.
func TestHandleSend_RejectsUnverifiedRouting(t *testing.T) {
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return &identity.IdentityRecord{Address: addr, RelayHints: []string{"/ip4/127.0.0.1/tcp/1"}}, nil
	}
	router := &fakeRelayRouter{}
	verifyRouting := func(context.Context, *identity.IdentityRecord) error {
		return fmt.Errorf("routing credential invalid")
	}
	h := api.NewMessageHandler(nil, lookup, router, nil, verifyRouting, logr.With(logr.M("test", true)))

	body := fmt.Sprintf(`{"sender_address":"alice@dmcn.me","sender_signature":"AAAA","envelope":%q,"recipient_address":"bob@dmcn.me"}`, validEnvelopeB64(t))
	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", body, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rr.Code, rr.Body.String())
	}
	if router.storeCalls != 0 || router.onionCalls != 0 {
		t.Fatalf("no relay must be contacted on routing-verify failure: store=%d onion=%d", router.storeCalls, router.onionCalls)
	}
}

func authedRequest(t *testing.T, method, path, body string, ss *webcore.SessionStore, address string) (*http.Request, string) {
	t.Helper()
	token, err := ss.Create(address)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)

	// Inject address into context as the auth middleware would.
	ctx := context.WithValue(req.Context(), webcore.ContextKeyAddress, address)
	return req.WithContext(ctx), token
}

func newTestMessageHandler(t *testing.T) (*api.MessageHandler, *webcore.SessionStore) {
	t.Helper()
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")

	var storedHash [32]byte
	storedHash[0] = 0xAB
	storePreSigned := func(ctx context.Context, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
		return storedHash, nil
	}

	h := api.NewMessageHandler(storePreSigned, nil, nil, nil, nil, logr.With(logr.M("test", true)))
	return h, ss
}

func TestHandleSend_MissingRecipientRelayHints(t *testing.T) {
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")

	storePreSigned := func(ctx context.Context, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
		return [32]byte{}, nil
	}

	// Create a mock registry lookup that returns a record with no relay hints.
	lookupNoHints := func(ctx context.Context, address string) (*identity.IdentityRecord, error) {
		return &identity.IdentityRecord{Address: address}, nil
	}

	h := api.NewMessageHandler(storePreSigned, lookupNoHints, nil, nil, nil, logr.With(logr.M("test", true)))

	// A minimal request with recipient_address. The envelope is invalid base64, so
	// the request fails before relay-hint checking — this just verifies the handler
	// accepts the current parameter set without breaking.
	body := `{"sender_address":"alice@dmcn.me","sender_signature":"AAAA","envelope":"AAAA","recipient_address":"bob@dmcn.me"}`
	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", body, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("expected non-200 for invalid envelope with recipient_address")
	}
}

func TestHandleSend_MissingAuth(t *testing.T) {
	h, _ := newTestMessageHandler(t)

	// No address in context → 401.
	req := httptest.NewRequest("POST", "/api/v1/messages/send", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSend_MissingFields(t *testing.T) {
	h, ss := newTestMessageHandler(t)

	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", `{}`, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)

	// Empty envelope field → 403 (sender mismatch since sender_address is empty).
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// sendStore drives HandleSend (non-onion) against a recipient with two hints and the
// given replication resolver, returning how many relays it STOREd to.
func sendStore(t *testing.T, replicate func(context.Context, string) bool) int {
	t.Helper()
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return &identity.IdentityRecord{
			Address:    addr,
			RelayHints: []string{"/ip4/127.0.0.1/tcp/1", "/ip4/127.0.0.1/tcp/2"},
		}, nil
	}
	router := &fakeRelayRouter{}
	h := api.NewMessageHandler(nil, lookup, router, replicate, nil, logr.With(logr.M("test", true)))
	body := fmt.Sprintf(`{"sender_address":"alice@dmcn.me","sender_signature":"AAAA","envelope":%q,"recipient_address":"bob@dmcn.me"}`, validEnvelopeB64(t))
	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", body, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	return router.storeCalls
}

func TestHandleSend_ReplicatesToAllHints(t *testing.T) {
	if n := sendStore(t, func(context.Context, string) bool { return true }); n != 2 {
		t.Fatalf("replicate: stored on %d relays, want 2 (all hints)", n)
	}
}

func TestHandleSend_FailoverStoresOnce(t *testing.T) {
	// nil resolver and a false resolver both mean failover (first reachable only).
	if n := sendStore(t, nil); n != 1 {
		t.Fatalf("failover (nil): stored on %d relays, want 1", n)
	}
	if n := sendStore(t, func(context.Context, string) bool { return false }); n != 1 {
		t.Fatalf("failover (false): stored on %d relays, want 1", n)
	}
}

// --- outbound to the legacy email world -------------------------------------------------------
//
// A legacy recipient has no DMCN identity to resolve, so the send is routed to this domain's
// bridge instead: the client has already sealed the envelope to the bridge's key, and the bridge
// reads the real destination out of the decrypted message. These tests pin the routing decision,
// which is the part that used to not exist — composing to an ordinary email address simply
// returned "recipient not found".

const legacyBridgeHint = "/ip4/10.0.0.9/tcp/7400/p2p/12D3KooWBridge"

// sendToLegacy drives HandleSend for a recipient the directory cannot resolve.
func sendToLegacy(t *testing.T, withBridge bool, verifyRouting func(context.Context, *identity.IdentityRecord) error) (*fakeRelayRouter, int) {
	t.Helper()
	ss, _ := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	lookup := func(context.Context, string) (*identity.IdentityRecord, error) {
		return nil, fmt.Errorf("not found") // gmail.com has no _dmcn record and never will
	}
	router := &fakeRelayRouter{}
	h := api.NewMessageHandler(nil, lookup, router, nil, verifyRouting, logr.With(logr.M("test", true)))
	if withBridge {
		h.SetBridgeResolver(func(context.Context) ([32]byte, string, error) {
			return [32]byte{7}, legacyBridgeHint, nil
		})
	}

	body := fmt.Sprintf(`{"sender_address":"alice@dmcn.me","sender_signature":"AAAA","envelope":%q,"recipient_address":"someone@gmail.com"}`, validEnvelopeB64(t))
	req, _ := authedRequest(t, "POST", "/api/v1/messages/send", body, ss, "alice@dmcn.me")
	rr := httptest.NewRecorder()
	h.HandleSend(rr, req)
	return router, rr.Code
}

// TestHandleSend_RoutesLegacyRecipientToTheBridge is the whole point: mail to an ordinary email
// address now goes somewhere instead of being refused.
func TestHandleSend_RoutesLegacyRecipientToTheBridge(t *testing.T) {
	router, code := sendToLegacy(t, true, nil)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if router.storeCalls != 1 {
		t.Fatalf("storeCalls = %d, want 1", router.storeCalls)
	}
	if len(router.lastHints) != 1 || router.lastHints[0] != legacyBridgeHint {
		t.Errorf("stored to %v, want the bridge hint %s", router.lastHints, legacyBridgeHint)
	}
}

// TestHandleSend_LegacyWithoutABridgeIsRefused keeps the failure honest on a deployment that runs
// no bridge: unreachable, rather than silently dropped or stored somewhere useless.
func TestHandleSend_LegacyWithoutABridgeIsRefused(t *testing.T) {
	router, code := sendToLegacy(t, false, nil)
	if code == http.StatusOK {
		t.Fatal("a legacy recipient was accepted with no bridge configured")
	}
	if router.storeCalls != 0 {
		t.Errorf("stored %d time(s) despite having nowhere to send", router.storeCalls)
	}
}

// TestHandleSend_LegacySkipsRoutingVerification pins a deliberate exception. Routing verification
// checks that a recipient's relay hints are attested by a routing credential — but a legacy
// recipient has no record and therefore no such credential, so running the check would reject
// every outbound-to-legacy message. The bridge is credential-verified during discovery instead,
// which is a stronger claim: it proves the peer may act as a bridge, not merely that a record
// was well-formed.
func TestHandleSend_LegacySkipsRoutingVerification(t *testing.T) {
	called := false
	deny := func(context.Context, *identity.IdentityRecord) error {
		called = true
		return fmt.Errorf("no routing credential")
	}
	router, code := sendToLegacy(t, true, deny)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d", code)
	}
	if called {
		t.Error("routing verification ran for a legacy recipient, which can never have a routing credential")
	}
	if router.storeCalls != 1 {
		t.Errorf("storeCalls = %d, want 1", router.storeCalls)
	}
}
