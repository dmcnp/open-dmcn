package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// IdentityHandler handles DHT identity lookup requests.
type IdentityHandler struct {
	lookup        func(ctx context.Context, address string) (*identity.IdentityRecord, error)
	verifyManaged func(ctx context.Context, rec *identity.IdentityRecord) (identity.VerificationTier, error)
	requiresOnion func(ctx context.Context, rec *identity.IdentityRecord) bool
	relayHints    func(ctx context.Context, address string) ([]string, error)
	adminCustody  func(ctx context.Context, domain string) bool
	log           logr.Logger
}

// NewIdentityHandler creates a new IdentityHandler. verifyManaged (optional, may
// be nil) cryptographically verifies a countersigned record's tier against the
// domain authority + DNS + removal records, so lookups can report a trustworthy
// verified_tier (used to anchor bridge attestations, gap #7/#9). requiresOnion
// (optional, may be nil) reports the effective onion-delivery policy (mailbox flag
// OR domain DAR), so the compose UI can reflect/lock the onion toggle. adminCustody
// (optional, may be nil) reports the domain's admin-key-custody policy bit —
// display-only (the managed-account badge); the enforcing gate lives in the
// register path, so this one fails open to false.
func NewIdentityHandler(
	lookup func(ctx context.Context, address string) (*identity.IdentityRecord, error),
	verifyManaged func(ctx context.Context, rec *identity.IdentityRecord) (identity.VerificationTier, error),
	requiresOnion func(ctx context.Context, rec *identity.IdentityRecord) bool,
	relayHints func(ctx context.Context, address string) ([]string, error),
	adminCustody func(ctx context.Context, domain string) bool,
	log logr.Logger,
) *IdentityHandler {
	return &IdentityHandler{
		lookup:        lookup,
		verifyManaged: verifyManaged,
		requiresOnion: requiresOnion,
		relayHints:    relayHints,
		adminCustody:  adminCustody,
		log:           log,
	}
}

// HandleRelayHints returns the load-aware mailbox relay hints for an address — the ranked
// mailbox relays of its domain. This is read-only placement (no reservation; the authoritative
// reservation happens at registration). It returns 503 when the domain has no reachable mailbox
// relay, so the client refuses to create/pair a mailbox it could never durably receive at,
// rather than embedding a placeholder hint.
func (h *IdentityHandler) HandleRelayHints(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address query parameter")
		return
	}
	hints, err := h.relayHints(r.Context(), address)
	if err != nil {
		h.log.Error("relay hint placement failed", logr.M("error", err.Error()), logr.M("address", address))
		writeError(w, http.StatusServiceUnavailable, "no mailbox relay available")
		return
	}
	if len(hints) == 0 {
		writeError(w, http.StatusServiceUnavailable, "no mailbox relay available")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"relay_hints": hints})
}

// HandleLookup handles an identity lookup by address query parameter.
func (h *IdentityHandler) HandleLookup(w http.ResponseWriter, r *http.Request) {
	address := r.URL.Query().Get("address")
	if address == "" {
		writeError(w, http.StatusBadRequest, "missing address query parameter")
		return
	}

	rec, err := h.lookup(r.Context(), address)
	if err != nil {
		h.log.Error("identity lookup failed", logr.M("error", err.Error()), logr.M("address", address))
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}

	// verified_tier is the cryptographically verified tier (vs the self-claimed
	// verification_tier). We only run the full DAR/DNS/removal verification when
	// the record actually carries an address credential — otherwise it can't exceed
	// its self-claimed tier and the extra DHT/DNS round-trips are pointless.
	// identity_unverifiable means the record CARRIED an address credential that
	// failed to verify (revoked binding, unauthorized issuer, broken DAR/DNS
	// chain) — clients should distrust such an identity (gap #7/#9).
	verifiedTier := int(rec.VerificationTier)
	unverifiable := false
	if h.verifyManaged != nil && rec.HasAddressCredential() {
		if tier, verr := h.verifyManaged(r.Context(), rec); verr != nil {
			verifiedTier = int(identity.TierUnverified)
			unverifiable = true
		} else {
			verifiedTier = int(tier)
		}
	}

	// require_onion is the effective onion-delivery policy (mailbox flag OR domain
	// DAR), so the compose UI can auto-enable + lock the onion toggle. The server
	// enforces it on send regardless of the UI.
	requireOnion := rec.RequireOnion
	if h.requiresOnion != nil {
		requireOnion = h.requiresOnion(r.Context(), rec)
	}

	// admin_key_custody surfaces the domain's custody policy bit so the client can
	// show the managed-account indicator (whitepaper §13.8-style disclosure).
	adminCustody := false
	if h.adminCustody != nil {
		adminCustody = h.adminCustody(r.Context(), domainverify.DomainOf(rec.Address))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":               rec.Address,
		"ed25519_pub":           base64.StdEncoding.EncodeToString(rec.Ed25519Public),
		"x25519_pub":            base64.StdEncoding.EncodeToString(rec.X25519Public[:]),
		"fingerprint":           rec.Fingerprint(),
		"verification_tier":     int(rec.VerificationTier),
		"verified_tier":         verifiedTier,
		"identity_unverifiable": unverifiable,
		// bridge_capability lets clients confirm a classification record's signer
		// is a registered bridge before trusting its legacy-auth verdict (gap #6).
		"bridge_capability": rec.BridgeCapability,
		"require_onion":     requireOnion,
		"admin_key_custody": adminCustody,
	})
}
