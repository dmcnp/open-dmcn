package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/petition"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
)

// petition_test.go drives the whole live-domain provisioning path end to end, with the root key
// held only by the test (standing in for the operator's offline machine) and never handed to the
// node — which is the property the entire design exists to produce.

const petDomain = "mesh.example"

type petFixture struct {
	t       *testing.T
	ctx     context.Context
	n       *node.Node
	root    *identity.IdentityKeyPair
	dar     *identity.DomainAuthorityRecord
	store   *petition.Store
	handler *webapi.PetitionHandler
	mux     *http.ServeMux
}

func newPetFixture(t *testing.T) *petFixture {
	t.Helper()
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx := context.Background()

	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       petDomain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	t.Cleanup(func() { n.Close() })

	// The operator's offline ceremony, done here in-process. The root NEVER reaches the node —
	// only the signed DAR does, exactly as the bundle carries it.
	// The operator's offline ceremony, done here in-process. The root NEVER reaches the node —
	// only the signed authority record does, pushed exactly as `dmcndcli domain publish` pushes it.
	root := mustKeyPair(t)
	dar := pushDAR(t, n, root)
	if err := adoptDomain(n, dar); err != nil {
		t.Fatalf("adopt domain: %v", err)
	}

	store, err := petition.NewStore(filepath.Join(t.TempDir(), "petitions.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := webapi.NewPetitionHandler(store, petDomain,
		func() ed25519.PublicKey { pub, _ := dar.RootKeyAt(time.Now()); return pub },
		n.RelayHints,
		func(ctx context.Context, rec *identity.IdentityRecord) error {
			_, perr := n.PublishIdentity(ctx, rec)
			return perr
		}, log)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/petition", h.HandleCreate)
	mux.HandleFunc("GET /api/v1/petition/status", h.HandleStatus)
	mux.HandleFunc("POST /api/v1/petition/complete", h.HandleComplete)
	mux.HandleFunc("POST /api/v1/admin/challenge", h.HandleAdminChallenge)
	mux.HandleFunc("POST /api/v1/admin/petition/get", h.HandleAdminGet)
	mux.HandleFunc("POST /api/v1/admin/petition/assign", h.HandleAdminAssign)

	return &petFixture{t: t, ctx: ctx, n: n, root: root, dar: dar, store: store, handler: h, mux: mux}
}

func (f *petFixture) do(method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var r *http.Request
	if body != nil {
		buf, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(buf))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// signAdmin runs the challenge-response the way the CLI does, with an arbitrary key so tests can
// try the wrong one.
func (f *petFixture) signAdmin(key *identity.IdentityKeyPair, sigContext, bound string) (nonce, sig string) {
	f.t.Helper()
	code, out := f.do("POST", "/api/v1/admin/challenge", struct{}{})
	if code != http.StatusOK {
		f.t.Fatalf("challenge: %d", code)
	}
	nonce, _ = out["nonce"].(string)
	raw, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		f.t.Fatal(err)
	}
	s := ed25519.Sign(key.Ed25519Private, webapi.AdminSignableBytes(sigContext, raw, bound))
	return nonce, base64.StdEncoding.EncodeToString(s)
}

// petitioner is the browser half: keys generated locally, only the public halves sent.
type petitioner struct {
	kp   *identity.IdentityKeyPair
	code string
}

func (f *petFixture) petition() *petitioner {
	f.t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		f.t.Fatal(err)
	}
	proof := ed25519.Sign(kp.Ed25519Private, petition.SignableBytes(kp.Ed25519Public, kp.X25519Public))
	code, out := f.do("POST", "/api/v1/petition", map[string]string{
		"ed25519_pub": base64.StdEncoding.EncodeToString(kp.Ed25519Public),
		"x25519_pub":  base64.StdEncoding.EncodeToString(kp.X25519Public[:]),
		"proof":       base64.StdEncoding.EncodeToString(proof),
	})
	if code != http.StatusOK {
		f.t.Fatalf("petition: %d %v", code, out)
	}
	c, _ := out["code"].(string)
	if c == "" {
		f.t.Fatal("no code returned")
	}
	return &petitioner{kp: kp, code: c}
}

// assign is the operator step: the offline root signs both credentials against the petitioner's
// public key and posts them.
func (f *petFixture) assign(p *petitioner, address string) (int, map[string]any) {
	f.t.Helper()
	nonce, sig := f.signAdmin(f.root, webapi.AdminGetContext, webapi.AdminGetBound(p.code))
	code, view := f.do("POST", "/api/v1/admin/petition/get", map[string]string{
		"code": p.code, "nonce": nonce, "signature": sig,
	})
	if code != http.StatusOK {
		f.t.Fatalf("admin get: %d %v", code, view)
	}
	var hints []string
	for _, h := range view["relay_hints"].([]any) {
		hints = append(hints, h.(string))
	}

	acPB, rcPB := f.signCredentials(p.kp, address, hints)
	nonce, sig = f.signAdmin(f.root, webapi.AdminAssignContext, webapi.AdminAssignBound(p.code, address))
	return f.do("POST", "/api/v1/admin/petition/assign", map[string]string{
		"code": p.code, "address": address,
		"address_credential": acPB, "routing_credential": rcPB,
		"nonce": nonce, "signature": sig,
	})
}

func (f *petFixture) signCredentials(kp *identity.IdentityKeyPair, address string, hints []string) (string, string) {
	f.t.Helper()
	now := time.Now().UTC()
	shell := &identity.IdentityRecord{
		Version: 1, Address: address,
		Ed25519Public: kp.Ed25519Public, X25519Public: kp.X25519Public, CreatedAt: now,
	}
	if err := shell.IssueAddressCredential(f.root, now); err != nil {
		f.t.Fatal(err)
	}
	if err := shell.IssueRoutingCredential(f.root, hints, now); err != nil {
		f.t.Fatal(err)
	}
	ac, _ := proto.Marshal(shell.AddressCredential.ToProto())
	rc, _ := proto.Marshal(shell.RoutingCredential.ToProto())
	return base64.StdEncoding.EncodeToString(ac), base64.StdEncoding.EncodeToString(rc)
}

// complete is the browser coming back: it learns its address by polling, self-signs a record for
// it, and submits.
func (f *petFixture) complete(p *petitioner) (int, map[string]any) {
	f.t.Helper()
	code, out := f.do("GET", "/api/v1/petition/status?code="+p.code, nil)
	if code != http.StatusOK {
		f.t.Fatalf("status: %d %v", code, out)
	}
	if out["status"] != "assigned" {
		f.t.Fatalf("status = %v, want assigned", out["status"])
	}
	address, _ := out["address"].(string)

	rec, err := identity.NewIdentityRecord(address, p.kp)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := rec.Sign(p.kp); err != nil {
		f.t.Fatal(err)
	}
	raw, err := proto.Marshal(rec.ToProto())
	if err != nil {
		f.t.Fatal(err)
	}
	return f.do("POST", "/api/v1/petition/complete", map[string]string{
		"code": p.code, "identity_record": base64.StdEncoding.EncodeToString(raw),
	})
}

// TestPetitionEndToEnd is the whole ceremony: petition, assign with a root the node never sees,
// complete, and the address becomes usable. The AddressUsable assertions are the point — that is
// the reader-side gate that was failing open before this change.
func TestPetitionEndToEnd(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()

	// Nothing is published yet, and nothing is claimed. A petition on its own is inert.
	if _, err := f.n.Lookup(f.ctx, "alice@"+petDomain); err == nil {
		t.Fatal("an address resolved before it was ever assigned")
	}

	if code, out := f.assign(p, "alice@"+petDomain); code != http.StatusOK {
		t.Fatalf("assign: %d %v", code, out)
	}
	if code, out := f.complete(p); code != http.StatusOK {
		t.Fatalf("complete: %d %v", code, out)
	}

	rec, err := f.n.Lookup(f.ctx, "alice@"+petDomain)
	if err != nil {
		t.Fatalf("lookup after completing: %v", err)
	}
	if rec.AddressCredential == nil {
		t.Fatal("published record carries no address credential — the countersign gate would refuse it")
	}
	if !rec.Ed25519Public.Equal(p.kp.Ed25519Public) {
		t.Fatal("published record is for a different key than petitioned")
	}
	if len(rec.RelayHints) == 0 {
		t.Error("published record has no relay hints — its mail has nowhere to go")
	}
	// The reader-side gate: on a RequireCountersign domain this is what decides whether the
	// mailbox may be used at all.
	if err := f.n.Registry().AddressUsable(f.ctx, rec); err != nil {
		t.Errorf("AddressUsable refused a properly petitioned address: %v", err)
	}
}

// TestSelfSignedRecordIsNotUsable pins the other half: on a live domain a record nobody attested is
// refused by the reader gate. Before this change the daemon signed a DAR with no policy flags, so
// this check passed for everyone and the offline root would have been decorative.
func TestSelfSignedRecordIsNotUsable(t *testing.T) {
	f := newPetFixture(t)
	if !f.dar.RequiresCountersign() {
		t.Fatal("the live DAR does not require countersigning — the gate is off")
	}

	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord("mallory@"+petDomain, kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatal(err)
	}
	if _, perr := f.n.PublishIdentity(f.ctx, rec); perr != nil {
		t.Logf("the node refused the record outright (%v) — the gate holds even earlier", perr)
	}
	if err := f.n.Registry().AddressUsable(f.ctx, rec); err == nil {
		t.Fatal("a self-signed, un-attested address is usable on a countersign-required domain")
	}
}

// TestAdminAuthRequiresTheRoot is the access control on the queue. A mailbox key — even a valid one
// on this domain — is not the domain root, and must not open it.
func TestAdminAuthRequiresTheRoot(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()

	impostor, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nonce, sig := f.signAdmin(impostor, webapi.AdminGetContext, webapi.AdminGetBound(p.code))
	code, out := f.do("POST", "/api/v1/admin/petition/get", map[string]string{
		"code": p.code, "nonce": nonce, "signature": sig,
	})
	if code == http.StatusOK {
		t.Fatalf("a non-root key read the petition queue: %v", out)
	}

	// No challenge outstanding at all.
	code, _ = f.do("POST", "/api/v1/admin/petition/get", map[string]string{
		"code": p.code, "nonce": nonce, "signature": sig,
	})
	if code == http.StatusOK {
		t.Fatal("a request with no outstanding challenge was accepted")
	}
}

// TestAdminNonceIsSingleUse stops a captured request being replayed — which for assign would mean
// re-pointing an address with a signature the admin made for something else.
func TestAdminNonceIsSingleUse(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()

	nonce, sig := f.signAdmin(f.root, webapi.AdminGetContext, webapi.AdminGetBound(p.code))
	body := map[string]string{"code": p.code, "nonce": nonce, "signature": sig}
	if code, out := f.do("POST", "/api/v1/admin/petition/get", body); code != http.StatusOK {
		t.Fatalf("first use rejected: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/admin/petition/get", body); code == http.StatusOK {
		t.Fatal("the same nonce+signature was accepted twice")
	}
}

// TestAdminSignatureIsBoundToItsOperation stops a signature made for a read being replayed as an
// assignment, which is the difference between looking and acting.
func TestAdminSignatureIsBoundToItsOperation(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()
	acPB, rcPB := f.signCredentials(p.kp, "alice@"+petDomain, []string{"/ip4/127.0.0.1/tcp/1/p2p/x"})

	// A signature over the GET context, replayed at assign.
	nonce, sig := f.signAdmin(f.root, webapi.AdminGetContext, webapi.AdminGetBound(p.code))
	code, _ := f.do("POST", "/api/v1/admin/petition/assign", map[string]string{
		"code": p.code, "address": "alice@" + petDomain,
		"address_credential": acPB, "routing_credential": rcPB,
		"nonce": nonce, "signature": sig,
	})
	if code == http.StatusOK {
		t.Fatal("a signature made for a read was accepted as an assignment")
	}

	// A signature bound to a DIFFERENT address than the one being assigned.
	nonce, sig = f.signAdmin(f.root, webapi.AdminAssignContext, webapi.AdminAssignBound(p.code, "bob@"+petDomain))
	code, _ = f.do("POST", "/api/v1/admin/petition/assign", map[string]string{
		"code": p.code, "address": "alice@" + petDomain,
		"address_credential": acPB, "routing_credential": rcPB,
		"nonce": nonce, "signature": sig,
	})
	if code == http.StatusOK {
		t.Fatal("a signature bound to a different address was accepted")
	}
}

// TestCompleteRequiresThePetitionedKey is what makes an overheard code worthless: whoever redeems
// it must hold the private key the petition proved.
func TestCompleteRequiresThePetitionedKey(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()
	if code, out := f.assign(p, "alice@"+petDomain); code != http.StatusOK {
		t.Fatalf("assign: %d %v", code, out)
	}

	// An eavesdropper with the code but their own keys.
	thief, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord("alice@"+petDomain, thief)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(thief); err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(rec.ToProto())
	code, out := f.do("POST", "/api/v1/petition/complete", map[string]string{
		"code": p.code, "identity_record": base64.StdEncoding.EncodeToString(raw),
	})
	if code == http.StatusOK {
		t.Fatalf("someone who only knew the code claimed the mailbox: %v", out)
	}

	// And the rightful holder still can.
	if code, out := f.complete(p); code != http.StatusOK {
		t.Fatalf("the rightful petitioner was blocked: %d %v", code, out)
	}
}

// TestCompleteRejectsADifferentAddress stops a petitioner from redeeming their assignment against
// an address they picked themselves — the property the whole design rests on.
func TestCompleteRejectsADifferentAddress(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()
	if code, out := f.assign(p, "alice@"+petDomain); code != http.StatusOK {
		t.Fatalf("assign: %d %v", code, out)
	}

	rec, err := identity.NewIdentityRecord("postmaster@"+petDomain, p.kp)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(p.kp); err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(rec.ToProto())
	code, out := f.do("POST", "/api/v1/petition/complete", map[string]string{
		"code": p.code, "identity_record": base64.StdEncoding.EncodeToString(raw),
	})
	if code == http.StatusOK {
		t.Fatalf("a petitioner chose their own address: %v", out)
	}
}

// TestStatusLeaksNothingBeforeAssignment keeps a polling browser (and anyone guessing codes) from
// learning anything the admin has not decided yet.
func TestStatusLeaksNothingBeforeAssignment(t *testing.T) {
	f := newPetFixture(t)
	p := f.petition()

	code, out := f.do("GET", "/api/v1/petition/status?code="+p.code, nil)
	if code != http.StatusOK {
		t.Fatalf("status: %d", code)
	}
	if out["status"] != "pending" {
		t.Errorf("status = %v, want pending", out["status"])
	}
	if _, leaked := out["address"]; leaked {
		t.Error("status returned an address before one was assigned")
	}

	// An unknown code is indistinguishable from an expired one.
	if code, _ := f.do("GET", "/api/v1/petition/status?code=0000-0000-0000", nil); code != http.StatusNotFound {
		t.Errorf("unknown code returned %d, want 404", code)
	}
}
