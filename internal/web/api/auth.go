// Package api implements the HTTP handlers for dmcnd's built-in web mail client:
// authentication, identity lookup, message send, mailbox sync, and — depending on
// how the domain is provisioned — either open registration (dev) or the mailbox
// petition flow (a live domain, whose root key is not on this machine).
//
// The backend holds no key material and no user directory. Every identity is
// resolved from its domain's fleet and verified by challenge-response against the
// record's own Ed25519 key; all message crypto happens in the browser.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/registry"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// AuthHandler handles login, logout, and identity import. It keeps NO user
// directory: identities are verified against the fleet-resolved registry record —
// the system of record — so any registered address can log into any client
// instance (challenge-response with the record's Ed25519 key; the relay's FETCH
// auth remains the real gate on mailbox access).
type AuthHandler struct {
	sessions       *webcore.SessionStore
	registryLookup func(ctx context.Context, address string) (*identity.IdentityRecord, error)
	challenges     *webcore.ChallengeStore
	log            logr.Logger
}

// NewAuthHandler creates a new AuthHandler. registryLookup resolves an address's
// IdentityRecord via its domain's fleet; login and import verify possession against it.
func NewAuthHandler(
	sessions *webcore.SessionStore,
	registryLookup func(ctx context.Context, address string) (*identity.IdentityRecord, error),
	log logr.Logger,
) *AuthHandler {
	return &AuthHandler{
		sessions:       sessions,
		registryLookup: registryLookup,
		challenges:     webcore.NewChallengeStore(60 * time.Second),
		log:            log,
	}
}

// lookupRecord resolves the address via its domain's fleet, writing the appropriate error
// response (404 unknown / 502 lookup failure) and returning ok=false on failure.
func (h *AuthHandler) lookupRecord(w http.ResponseWriter, r *http.Request, address string) (*identity.IdentityRecord, bool) {
	if h.registryLookup == nil {
		writeError(w, http.StatusNotImplemented, "directory lookup not available")
		return nil, false
	}
	rec, err := h.registryLookup(r.Context(), address)
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			writeError(w, http.StatusNotFound, "address is not registered in the directory")
			return nil, false
		}
		h.log.Warn("directory lookup failed", logr.M("address", address), logr.M("error", err.Error()))
		writeError(w, http.StatusBadGateway, "could not verify identity in the directory")
		return nil, false
	}
	return rec, true
}

// loginRequest is the JSON body for HandleLogin.
type loginRequest struct {
	Address string `json:"address"`
}

// HandleLogin handles the first step of login: it confirms the address is
// registered on its domain's fleet and returns its public key plus a challenge nonce.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Address == "" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rec, ok := h.lookupRecord(w, r, req.Address)
	if !ok {
		return
	}

	nonce, err := h.challenges.Issue(req.Address)
	if err != nil {
		h.log.Error("failed to generate challenge nonce", logr.M("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	// The server returns no key material — only the challenge to sign and the
	// public key. The browser unlocks its own local keystore.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ed25519_pub":     base64.StdEncoding.EncodeToString(rec.Ed25519Public),
		"challenge_nonce": base64.StdEncoding.EncodeToString(nonce),
	})
}

// loginVerifyRequest is the JSON body for HandleLoginVerify.
type loginVerifyRequest struct {
	Address            string `json:"address"`
	ChallengeSignature string `json:"challenge_signature"`
}

// HandleLoginVerify handles the second step of login: it verifies the signed
// challenge against the resolved record's Ed25519 key and mints a session.
func (h *AuthHandler) HandleLoginVerify(w http.ResponseWriter, r *http.Request) {
	var req loginVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	nonce, ok := h.challenges.Get(req.Address)
	if !ok {
		writeError(w, http.StatusBadRequest, "no pending challenge for address")
		return
	}

	rec, ok := h.lookupRecord(w, r, req.Address)
	if !ok {
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.ChallengeSignature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}

	if err := crypto.Verify(rec.Ed25519Public, nonce, sigBytes); err != nil {
		writeError(w, http.StatusUnauthorized, "challenge signature verification failed")
		return
	}

	h.challenges.Delete(req.Address)

	token, err := h.sessions.Create(req.Address)
	if err != nil {
		h.log.Error("failed to create session", logr.M("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"session_token": token})
}

// importChallengeRequest is the JSON body for HandleImportChallenge.
type importChallengeRequest struct {
	Address string `json:"address"`
}

// HandleImportChallenge begins importing an existing (e.g. CLI-created) identity
// into this client. It confirms the address is registered in the directory and
// returns the authoritative public keys plus a challenge nonce; the browser
// proves possession of the private key by signing the nonce. Nothing is published.
func (h *AuthHandler) HandleImportChallenge(w http.ResponseWriter, r *http.Request) {
	var req importChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Address == "" {
		writeError(w, http.StatusBadRequest, "address required")
		return
	}

	rec, ok := h.lookupRecord(w, r, req.Address)
	if !ok {
		return
	}

	nonce, err := h.challenges.Issue(req.Address)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ed25519_pub":     base64.StdEncoding.EncodeToString(rec.Ed25519Public),
		"x25519_pub":      base64.StdEncoding.EncodeToString(rec.X25519Public[:]),
		"challenge_nonce": base64.StdEncoding.EncodeToString(nonce),
	})
}

// importRequest is the JSON body for HandleImport. It carries only the possession
// proof — the encrypted keystore stays in the browser, never sent here.
type importRequest struct {
	Address            string `json:"address"`
	ChallengeSignature string `json:"challenge_signature"`
}

// HandleImport completes an import: it verifies the signed challenge against the
// directory's authoritative Ed25519 key (proof the caller holds the identity's
// private key) and mints a session. Because login verifies against the resolved
// record, there is no local record to create — import is login for an identity whose
// keys arrived on this device out-of-band. No keys are generated, stored, or published.
func (h *AuthHandler) HandleImport(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate the pending challenge.
	nonce, ok := h.challenges.Get(req.Address)
	if !ok {
		writeError(w, http.StatusBadRequest, "no pending import challenge for address")
		return
	}

	// Authoritative keys come from the directory, not the client.
	rec, ok := h.lookupRecord(w, r, req.Address)
	if !ok {
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.ChallengeSignature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}
	if err := crypto.Verify(rec.Ed25519Public, nonce, sigBytes); err != nil {
		writeError(w, http.StatusUnauthorized, "challenge signature does not match the registered identity")
		return
	}
	h.challenges.Delete(req.Address)

	token, err := h.sessions.Create(req.Address)
	if err != nil {
		h.log.Error("failed to create session", logr.M("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	h.log.Info("identity imported", logr.M("address", req.Address))

	writeJSON(w, http.StatusOK, map[string]string{"session_token": token})
}

// HandleLogout handles session logout.
func (h *AuthHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" || token == authHeader {
		writeError(w, http.StatusBadRequest, "missing bearer token")
		return
	}

	h.sessions.Delete(token)
	w.WriteHeader(http.StatusNoContent)
}

// JSON response helpers — thin aliases over the shared webcore implementations
// so handler code stays terse.
var (
	writeJSON      = webcore.WriteJSON
	writeError     = webcore.WriteError
	writeErrorCode = webcore.WriteErrorCode
)
