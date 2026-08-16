package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/web/api"
)

// signedRecordB64 builds a browser-equivalent self-signed IdentityRecord and returns its keypair
// plus the base64 proto bytes the register endpoint expects.
func signedRecordB64(t *testing.T, address string) (*identity.IdentityKeyPair, string) {
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
	b, err := proto.Marshal(rec.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	return kp, base64.StdEncoding.EncodeToString(b)
}

func registerBody(address, recB64 string) string {
	return fmt.Sprintf(`{"address":%q,"identity_record":%q}`, address, recB64)
}

func postRegister(h *api.RegisterHandler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/v1/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.HandleRegister(rr, req)
	return rr
}

func TestRegister_HappyPath(t *testing.T) {
	var got string
	provision := func(_ context.Context, rec *identity.IdentityRecord) (string, error) {
		got = rec.Address
		return "active", nil
	}
	h := api.NewRegisterHandler(provision, logr.With(logr.M("test", true)))

	_, recB64 := signedRecordB64(t, "alice@dmcn.me")
	rr := postRegister(h, registerBody("alice@dmcn.me", recB64))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got != "alice@dmcn.me" {
		t.Fatalf("provision saw address %q, want alice@dmcn.me", got)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["status"] != "active" {
		t.Fatalf("status = %q, want active", resp["status"])
	}
}

// A record whose self-signature doesn't verify (tampered bytes) is rejected before provisioning.
func TestRegister_TamperedRecordRejected(t *testing.T) {
	called := false
	provision := func(context.Context, *identity.IdentityRecord) (string, error) { called = true; return "active", nil }
	h := api.NewRegisterHandler(provision, logr.With(logr.M("test", true)))

	_, recB64 := signedRecordB64(t, "bob@dmcn.me")
	raw, _ := base64.StdEncoding.DecodeString(recB64)
	raw[len(raw)/2] ^= 0xff // flip a byte inside the record
	tampered := base64.StdEncoding.EncodeToString(raw)

	rr := postRegister(h, registerBody("bob@dmcn.me", tampered))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a tampered record, got %d: %s", rr.Code, rr.Body.String())
	}
	if called {
		t.Fatal("provision must not run for an unverifiable record")
	}
}

// A request whose address doesn't match the record is rejected.
func TestRegister_AddressMismatchRejected(t *testing.T) {
	provision := func(context.Context, *identity.IdentityRecord) (string, error) { return "active", nil }
	h := api.NewRegisterHandler(provision, logr.With(logr.M("test", true)))

	_, recB64 := signedRecordB64(t, "carol@dmcn.me")
	rr := postRegister(h, registerBody("mallory@dmcn.me", recB64))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an address mismatch, got %d", rr.Code)
	}
}

// Provision sentinels map to their HTTP codes.
func TestRegister_ProvisionErrorsMap(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{api.ErrRegisterExists, http.StatusConflict},
		{api.ErrRegisterDomainNotServed, http.StatusForbidden},
		{fmt.Errorf("some internal failure"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		provision := func(context.Context, *identity.IdentityRecord) (string, error) { return "", c.err }
		h := api.NewRegisterHandler(provision, logr.With(logr.M("test", true)))
		_, recB64 := signedRecordB64(t, "dan@dmcn.me")
		rr := postRegister(h, registerBody("dan@dmcn.me", recB64))
		if rr.Code != c.want {
			t.Fatalf("err %v: expected %d, got %d", c.err, c.want, rr.Code)
		}
	}
}
