package api

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/petition"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// petition.go is how a person gets a mailbox on a live domain whose root key is not on this
// machine. See internal/petition for why the flow has the shape it does.
//
// There are two audiences and they are kept apart. The petitioner's endpoints are public and
// unauthenticated — anyone who can reach the daemon may file a petition, which is safe precisely
// because a petition confers nothing until an admin acts on it. The admin's endpoints are
// authenticated by a signature from the DOMAIN ROOT, verified against the root key in the DAR
// this node already holds and trusts. That means no shared secret, no admin password, and no new
// trust anchor: the same key that anchors the domain in DNS is the one that opens the queue, and
// it stays wherever the operator keeps it.
//
// The three-step split (petition, assign, complete) is forced by self-certifying records. A
// record's owner self-signature covers its address, so the record cannot exist until the address
// is known — which is after the admin has acted. The admin therefore signs the two operator
// credentials against the petitioner's PUBLIC key, the node parks them, and the browser comes
// back to self-sign the record they attach to.

// Signature contexts. Each op has its own, so a signature captured from one can never be
// replayed as the other — an admin who signs a read must not thereby have signed an assignment.
const (
	adminGetContext    = "dmcn-petition-admin-get-v1\x00"
	adminAssignContext = "dmcn-petition-admin-assign-v1\x00"
)

// adminChallengeKey is the ChallengeStore key for the admin nonce. One per domain: a self-hosted
// daemon has one admin, and a second concurrent ceremony simply re-issues.
func adminChallengeKey(domain string) string { return "petition-admin@" + domain }

// PublishFunc publishes a completed identity record to the local store and the fleet.
type PublishFunc func(ctx context.Context, rec *identity.IdentityRecord) error

// PetitionHandler backs the petition endpoints.
type PetitionHandler struct {
	store      *petition.Store
	domain     string
	rootPub    func() ed25519.PublicKey
	relayHints func() []string
	publish    PublishFunc
	challenges *webcore.ChallengeStore
	log        logr.Logger
}

// NewPetitionHandler builds the handler. rootPub returns the domain root's public key as carried
// in the DAR the node serves; relayHints returns this node's own mailbox hints, which the admin
// needs in order to sign a routing credential without being able to reach the node's config.
func NewPetitionHandler(store *petition.Store, domain string, rootPub func() ed25519.PublicKey, relayHints func() []string, publish PublishFunc, log logr.Logger) *PetitionHandler {
	return &PetitionHandler{
		store:      store,
		domain:     domain,
		rootPub:    rootPub,
		relayHints: relayHints,
		publish:    publish,
		challenges: webcore.NewChallengeStore(60 * time.Second),
		log:        log,
	}
}

// ---------------------------------------------------------------- petitioner

type petitionCreateRequest struct {
	Ed25519Pub string `json:"ed25519_pub"`
	X25519Pub  string `json:"x25519_pub"`
	Proof      string `json:"proof"`
}

// HandleCreate files a petition and returns the code the petitioner reads to their admin.
//
// It deliberately returns nothing else. No address is chosen, nothing is published, and the
// response reveals nothing about the domain — so a flood of these costs an attacker effort and
// gains them nothing.
func (h *PetitionHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req petitionCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	edPub, xPub, ok := decodeKeys(w, req.Ed25519Pub, req.X25519Pub)
	if !ok {
		return
	}
	proof, err := base64.StdEncoding.DecodeString(req.Proof)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid proof encoding")
		return
	}

	p, err := h.store.Create(edPub, xPub, proof, time.Now())
	switch {
	case errors.Is(err, petition.ErrBadProof):
		writeErrorCode(w, http.StatusBadRequest, "bad_proof", "the signature does not prove possession of this key")
		return
	case errors.Is(err, petition.ErrQueueFull):
		writeErrorCode(w, http.StatusTooManyRequests, "queue_full", "too many pending petitions — try again later")
		return
	case err != nil:
		h.log.Errorf("create petition: %v", err)
		writeError(w, http.StatusInternalServerError, "could not file the petition")
		return
	}

	h.log.Infof("mailbox petition filed: code %s (key %s), expires %s",
		p.Code, shortKey(p.Ed25519Public), p.ExpiresAt.Format(time.RFC3339))
	writeJSON(w, http.StatusOK, map[string]any{
		"code":       p.Code,
		"expires_at": p.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// HandleStatus lets the petitioner's browser poll for the address the admin assigned, so nobody
// has to read an email address down a phone line — the code was the only thing that had to travel
// by voice.
//
// A code is a bearer token for exactly this: learning an address that is about to be public
// anyway. It reveals nothing else, and the record it names cannot be completed by anyone who does
// not hold the petitioner's private key.
func (h *PetitionHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}
	p, err := h.store.Get(code, time.Now())
	if err != nil {
		// Expired and never-existed are the same answer on purpose: a probe learns nothing
		// about which codes were ever real.
		writeErrorCode(w, http.StatusNotFound, "unknown_code", "no pending petition for that code")
		return
	}
	if !p.Assigned() {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "pending",
			"expires_at": p.ExpiresAt.UTC().Format(time.RFC3339),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "assigned",
		"address": p.Address,
	})
}

type petitionCompleteRequest struct {
	Code           string `json:"code"`
	IdentityRecord string `json:"identity_record"` // base64 proto, self-signed by the petitioner
}

// HandleComplete takes the petitioner's self-signed record for their assigned address, attaches
// the operator credentials the admin left behind, and publishes it.
//
// Everything here is a match against what was already agreed: the record must be for the assigned
// address and carry the exact keys the petition proved possession of. That is what stops a code —
// which travelled by voice and may have been overheard — from being redeemed by anyone else.
func (h *PetitionHandler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	var req petitionCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p, err := h.store.Get(strings.TrimSpace(req.Code), time.Now())
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "unknown_code", "no pending petition for that code")
		return
	}
	if !p.Assigned() {
		writeErrorCode(w, http.StatusConflict, "not_assigned", "this petition has not been assigned an address yet")
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
	if err := rec.Verify(); err != nil {
		writeError(w, http.StatusBadRequest, "identity record signature invalid: "+err.Error())
		return
	}
	if rec.Address != p.Address {
		writeErrorCode(w, http.StatusBadRequest, "address_mismatch", "the record is not for the assigned address")
		return
	}
	if !rec.Ed25519Public.Equal(p.Ed25519Public) || rec.X25519Public != p.X25519Public {
		writeErrorCode(w, http.StatusForbidden, "key_mismatch", "the record does not carry the keys this petition proved")
		return
	}

	// Attach only the operator-owned fields. VerificationTier is deliberately NOT touched: it is
	// covered by the owner self-signature, so writing it here would invalidate the record we just
	// verified. The tier a reader acts on is derived from the address credential anyway
	// (registry.VerifyManagedIdentity), which is the correct direction — attestation decides
	// trust, not the claim printed on the record.
	rec.AddressCredential = p.AddressCredential
	rec.RoutingCredential = p.RoutingCredential
	if p.RoutingCredential != nil {
		rec.RelayHints = p.RoutingCredential.RelayHints
	}

	if err := h.publish(r.Context(), rec); err != nil {
		h.log.Errorf("publish petitioned record %s: %v", rec.Address, err)
		writeError(w, http.StatusInternalServerError, "could not publish the record")
		return
	}
	if err := h.store.Complete(p.Code); err != nil {
		// The record is live; the queue entry is now stale rather than harmful. Log and move on.
		h.log.Warnf("petition %s published but not cleared from the queue: %v", p.Code, err)
	}

	h.log.Successf("mailbox %s provisioned from petition %s", rec.Address, p.Code)
	writeJSON(w, http.StatusOK, map[string]any{"status": "active", "address": rec.Address})
}

// --------------------------------------------------------------------- admin

// HandleAdminChallenge issues the nonce the admin's offline root signs. Unauthenticated by
// necessity — it is the first half of proving who you are — and harmless: a nonce is worth
// nothing without the root key, and it is single-use.
func (h *PetitionHandler) HandleAdminChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, err := h.challenges.Issue(adminChallengeKey(h.domain))
	if err != nil {
		h.log.Errorf("issue admin challenge: %v", err)
		writeError(w, http.StatusInternalServerError, "could not issue a challenge")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	})
}

type adminGetRequest struct {
	Code      string `json:"code"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// HandleAdminGet returns one petition, by code, to a caller who can sign with the domain root.
//
// By code only: there is no list endpoint, and there never should be. The admin is meant to act
// on a code somebody gave them, not to browse a queue — which is what keeps unwanted petitions
// from being work.
func (h *PetitionHandler) HandleAdminGet(w http.ResponseWriter, r *http.Request) {
	var req adminGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	code := strings.TrimSpace(req.Code)
	if !h.verifyAdmin(w, req.Nonce, req.Signature, adminGetContext, code) {
		return
	}
	p, err := h.store.Get(code, time.Now())
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "unknown_code", "no pending petition for that code")
		return
	}

	resp := map[string]any{
		"code":        p.Code,
		"ed25519_pub": base64.StdEncoding.EncodeToString(p.Ed25519Public),
		"x25519_pub":  base64.StdEncoding.EncodeToString(p.X25519Public[:]),
		"created_at":  p.CreatedAt.UTC().Format(time.RFC3339),
		"expires_at":  p.ExpiresAt.UTC().Format(time.RFC3339),
		"assigned":    p.Assigned(),
		// The admin machine has no way to know this node's mailbox hints, and needs them to
		// sign a routing credential. They are public routing data.
		"relay_hints": h.relayHints(),
		"domain":      h.domain,
	}
	if p.Assigned() {
		resp["address"] = p.Address
	}
	writeJSON(w, http.StatusOK, resp)
}

type adminAssignRequest struct {
	Code              string `json:"code"`
	Address           string `json:"address"`
	AddressCredential string `json:"address_credential"` // base64 proto, root-signed
	RoutingCredential string `json:"routing_credential"` // base64 proto, root-signed
	Nonce             string `json:"nonce"`
	Signature         string `json:"signature"`
}

// HandleAdminAssign records the admin's decision: the address, and the two credentials the
// offline root signed for it.
//
// The credentials are re-verified here against the same root key that authorised the call, so a
// bug or a mix-up on the admin's side cannot park credentials this node would later refuse to
// serve — the failure surfaces now, to the person who can fix it, rather than at the petitioner's
// browser an hour later.
func (h *PetitionHandler) HandleAdminAssign(w http.ResponseWriter, r *http.Request) {
	var req adminAssignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	code := strings.TrimSpace(req.Code)
	address := strings.TrimSpace(req.Address)
	if !h.verifyAdmin(w, req.Nonce, req.Signature, adminAssignContext, code+"\x00"+address) {
		return
	}

	local, addrDomain, ok := strings.Cut(address, "@")
	if !ok || local == "" {
		writeErrorCode(w, http.StatusBadRequest, "invalid_address", "invalid address")
		return
	}
	if !strings.EqualFold(addrDomain, h.domain) {
		writeErrorCode(w, http.StatusForbidden, "domain_not_served", ErrRegisterDomainNotServed.Error())
		return
	}

	p, err := h.store.Get(code, time.Now())
	if err != nil {
		writeErrorCode(w, http.StatusNotFound, "unknown_code", "no pending petition for that code")
		return
	}

	addrCred, ok := h.decodeCred(w, req.AddressCredential, "address_credential", p, address)
	if !ok {
		return
	}
	routeCred, ok := h.decodeCred(w, req.RoutingCredential, "routing_credential", p, address)
	if !ok {
		return
	}

	if _, err := h.store.Assign(code, address, addrCred, routeCred, time.Now()); err != nil {
		switch {
		case errors.Is(err, petition.ErrAssigned):
			writeErrorCode(w, http.StatusConflict, "already_assigned", "this petition has already been assigned an address")
		case errors.Is(err, petition.ErrExpired):
			writeErrorCode(w, http.StatusGone, "expired", "this petition has expired")
		default:
			h.log.Errorf("assign petition %s: %v", code, err)
			writeError(w, http.StatusInternalServerError, "could not assign the address")
		}
		return
	}

	h.log.Successf("petition %s assigned %s — waiting for the petitioner to complete it", code, address)
	writeJSON(w, http.StatusOK, map[string]any{"status": "assigned", "address": address})
}

// decodeCred parses one root-signed credential and checks it says what the assignment says: same
// subject key as the petition, same address, valid signature from the domain root.
func (h *PetitionHandler) decodeCred(w http.ResponseWriter, encoded, field string, p *petition.Petition, address string) (*identity.Credential, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		writeError(w, http.StatusBadRequest, "invalid "+field+" encoding")
		return nil, false
	}
	cred, err := identity.CredentialFromProtoBytes(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+field+": "+err.Error())
		return nil, false
	}
	if err := cred.VerifySignature(); err != nil {
		writeError(w, http.StatusBadRequest, field+" signature invalid: "+err.Error())
		return nil, false
	}
	root := h.rootPub()
	if root == nil || !cred.IssuerPub.Equal(root) {
		writeErrorCode(w, http.StatusForbidden, "not_root_signed", field+" was not signed by this domain's root key")
		return nil, false
	}
	if !cred.Subject.Equal(p.Ed25519Public) {
		writeErrorCode(w, http.StatusBadRequest, "subject_mismatch", field+" is for a different key than this petition")
		return nil, false
	}
	if cred.Address != address {
		writeErrorCode(w, http.StatusBadRequest, "address_mismatch", field+" is for a different address than the one being assigned")
		return nil, false
	}
	return cred, true
}

// verifyAdmin checks a one-shot root signature over (context ‖ nonce ‖ bound). The nonce is
// consumed whatever the outcome, so a captured request cannot be replayed.
func (h *PetitionHandler) verifyAdmin(w http.ResponseWriter, nonceB64, sigB64, sigContext, bound string) bool {
	key := adminChallengeKey(h.domain)
	want, ok := h.challenges.Get(key)
	if !ok {
		writeErrorCode(w, http.StatusUnauthorized, "no_challenge", "no outstanding challenge — request one first")
		return false
	}
	h.challenges.Delete(key)

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil || len(nonce) == 0 {
		writeError(w, http.StatusBadRequest, "invalid nonce encoding")
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return false
	}
	if !hmac.Equal(nonce, want) {
		writeErrorCode(w, http.StatusUnauthorized, "stale_challenge", "that challenge is not the outstanding one")
		return false
	}
	root := h.rootPub()
	if root == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "no_root_key", "this node does not know the domain root key")
		return false
	}
	if !ed25519.Verify(root, adminSignableBytes(sigContext, nonce, bound), sig) {
		writeErrorCode(w, http.StatusForbidden, "bad_signature", "not signed by this domain's root key")
		return false
	}
	return true
}

// AdminSignableBytes is what the admin's root key signs for an operator call. Exported so the CLI
// signs exactly what the daemon verifies — the two must never drift.
func AdminSignableBytes(sigContext string, nonce []byte, bound string) []byte {
	return adminSignableBytes(sigContext, nonce, bound)
}

func adminSignableBytes(sigContext string, nonce []byte, bound string) []byte {
	b := make([]byte, 0, len(sigContext)+len(nonce)+len(bound))
	b = append(b, sigContext...)
	b = append(b, nonce...)
	b = append(b, bound...)
	return b
}

// Signature contexts + bound-value builders, exported for the CLI.
func AdminGetBound(code string) string             { return code }
func AdminAssignBound(code, address string) string { return code + "\x00" + address }

const (
	AdminGetContext    = adminGetContext
	AdminAssignContext = adminAssignContext
)

func decodeKeys(w http.ResponseWriter, edB64, xB64 string) (ed25519.PublicKey, [32]byte, bool) {
	var xPub [32]byte
	edPub, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil || len(edPub) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid ed25519_pub")
		return nil, xPub, false
	}
	xRaw, err := base64.StdEncoding.DecodeString(xB64)
	if err != nil || len(xRaw) != 32 {
		writeError(w, http.StatusBadRequest, "invalid x25519_pub")
		return nil, xPub, false
	}
	copy(xPub[:], xRaw)
	return edPub, xPub, true
}

func shortKey(k ed25519.PublicKey) string {
	s := base64.StdEncoding.EncodeToString(k)
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
