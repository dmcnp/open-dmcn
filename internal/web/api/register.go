package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// register.go is the reference daemon's self-service registration. In the DMCN PRODUCT this
// lives on a separate funnel service (dmcn-b2c) wrapped in registration policy, DNS proofs,
// fleet permits, billing, and a user directory. In the OPEN protocol the daemon simply IS the
// operator for its one domain, so registration reduces to: verify the browser's self-signed
// IdentityRecord, then (operator-side) attach a routing credential and publish it. Zero-knowledge
// is preserved end-to-end — the browser generates the keys and self-signs; only the signed public
// record reaches the server.

var (
	// ErrRegisterDomainNotServed: the requested address is not on the domain this daemon serves.
	ErrRegisterDomainNotServed = errors.New("address domain is not served by this node")
	// ErrRegisterExists: an identity is already registered for this address.
	ErrRegisterExists = errors.New("address is already registered")
	// ErrRegisterInvalidAddress: the address local-part is empty or malformed.
	ErrRegisterInvalidAddress = errors.New("invalid address")
)

// ProvisionFunc is the operator-side half of registration: given a verified, self-signed record,
// attach the operator routing attestation and publish it to the fleet, returning the account
// status ("active"). It is where the daemon applies its domain + duplicate checks.
type ProvisionFunc func(ctx context.Context, rec *identity.IdentityRecord) (status string, err error)

// RegisterHandler backs POST /api/v1/register.
type RegisterHandler struct {
	provision ProvisionFunc
	log       logr.Logger
}

// NewRegisterHandler builds a RegisterHandler around the operator provision hook.
func NewRegisterHandler(provision ProvisionFunc, log logr.Logger) *RegisterHandler {
	return &RegisterHandler{provision: provision, log: log}
}

// registerRequest mirrors the browser payload: the self-signed IdentityRecord (authoritative)
// plus the loose public keys/signature (kept for wire-compatibility with the product client).
type registerRequest struct {
	Address        string `json:"address"`
	Ed25519Pub     string `json:"ed25519_pub"`
	X25519Pub      string `json:"x25519_pub"`
	IdentityRecord string `json:"identity_record"` // base64 proto (full signed record)
	SelfSignature  string `json:"self_signature"`
}

// HandleRegister verifies a self-signed IdentityRecord and provisions the account. It returns
// only the account status — it mints NO session; the browser logs in with its fresh keys next.
func (h *RegisterHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	recBytes, err := base64.StdEncoding.DecodeString(req.IdentityRecord)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity_record encoding")
		return
	}
	rec, err := identity.IdentityRecordFromProtoBytes(recBytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identity record: "+err.Error())
		return
	}

	// The record is self-certifying: verify the owner self-signature before trusting any field.
	if err := rec.Verify(); err != nil {
		writeError(w, http.StatusBadRequest, "identity record signature invalid: "+err.Error())
		return
	}
	// The record must be for the address the client claims (defends against a mismatched payload).
	if req.Address == "" || rec.Address != req.Address {
		writeError(w, http.StatusBadRequest, "address does not match identity record")
		return
	}
	if local, _, ok := strings.Cut(rec.Address, "@"); !ok || local == "" {
		writeErrorCode(w, http.StatusBadRequest, "invalid_address", "invalid address")
		return
	}

	status, err := h.provision(r.Context(), rec)
	if err != nil {
		switch {
		case errors.Is(err, ErrRegisterDomainNotServed):
			writeErrorCode(w, http.StatusForbidden, "domain_not_served", ErrRegisterDomainNotServed.Error())
		case errors.Is(err, ErrRegisterExists):
			writeErrorCode(w, http.StatusConflict, "already_registered", ErrRegisterExists.Error())
		case errors.Is(err, ErrRegisterInvalidAddress):
			writeErrorCode(w, http.StatusBadRequest, "invalid_address", ErrRegisterInvalidAddress.Error())
		default:
			h.log.Error("registration failed", logr.M("address", rec.Address), logr.M("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "registration failed")
		}
		return
	}

	h.log.Success("account registered", logr.M("address", rec.Address), logr.M("status", status))
	writeJSON(w, http.StatusOK, map[string]string{"status": status})
}
