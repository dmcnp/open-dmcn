package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/pairing"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// PairHandler is what a device with no account yet needs to ask to join one
// (SPEC_EXT_DEVICES.md §8). It has two open endpoints: publish the newcomer's throwaway
// identity, and mint a short session bound to that throwaway address. Everything after that
// (sending the request, reading the answer) uses the ordinary authenticated endpoints under
// that session.
//
// Both are restricted to pairing.local addresses, so neither can publish or open a session
// for a real identity. Nothing rests on them for security: the mailbox still asks for the
// throwaway key's signature, and the answer is sealed to that key and signed by the account's.
type PairHandler struct {
	sessions *webcore.SessionStore
	publish  func(ctx context.Context, rec *identity.IdentityRecord) error
	log      logr.Logger
}

// NewPairHandler creates a PairHandler. publish stores a self-signed pairing.local record so
// its mailbox can be found; it verifies the record's signature itself.
func NewPairHandler(sessions *webcore.SessionStore, publish func(ctx context.Context, rec *identity.IdentityRecord) error, log logr.Logger) *PairHandler {
	return &PairHandler{sessions: sessions, publish: publish, log: log}
}

type pairRegisterRequest struct {
	IdentityRecord string `json:"identity_record"` // base64 protobuf of a self-signed IdentityRecord
}

// HandleRegister publishes a newcomer's throwaway identity.
func (h *PairHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	var req pairRegisterRequest
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
	if !pairing.IsEphemeralAddress(rec.Address) {
		writeError(w, http.StatusForbidden, "pair register is only for pairing addresses")
		return
	}
	if err := h.publish(r.Context(), rec); err != nil {
		h.log.Warn("pair register failed", logr.M("error", err.Error()))
		writeError(w, http.StatusBadGateway, "failed to publish the pairing identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type pairSessionRequest struct {
	EphemeralAddress string `json:"ephemeral_address"`
}

// HandleSession mints a session bound to a throwaway address, so the newcomer can use the
// mailbox and send endpoints as that identity. The token confers nothing by itself: every
// mailbox request still needs the throwaway key's signature.
func (h *PairHandler) HandleSession(w http.ResponseWriter, r *http.Request) {
	var req pairSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if !pairing.IsEphemeralAddress(req.EphemeralAddress) {
		writeError(w, http.StatusForbidden, "pair session is only for pairing addresses")
		return
	}
	token, err := h.sessions.Create(req.EphemeralAddress)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create pairing session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"session_token": token})
}
