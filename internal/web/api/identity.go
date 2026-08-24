package api

import (
	"context"
	"encoding/base64"
	"net/http"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/identity"
)

// IdentityHandler handles identity lookup requests.
type IdentityHandler struct {
	lookup        func(ctx context.Context, address string) (*identity.IdentityRecord, error)
	verifyManaged func(ctx context.Context, rec *identity.IdentityRecord) (identity.VerificationTier, error)
	requiresOnion func(ctx context.Context, rec *identity.IdentityRecord) bool
	relayHints    func(ctx context.Context, address string) ([]string, error)
	// resolveBridge finds this domain's outbound bridge for legacy (non-DMCN) recipients.
	// Optional: nil means the deployment has no bridge and legacy addresses stay unroutable.
	resolveBridge BridgeResolver
	log           logr.Logger
}

// BridgeResolver discovers the outbound bridge for a sender domain: where to STORE mail bound for
// the legacy email world, and the key to seal it under. See node.ResolveBridge.
type BridgeResolver func(ctx context.Context) (x25519Pub [32]byte, multiaddr string, err error)

// SetBridgeResolver installs the outbound-bridge resolver. Wired separately from the constructor
// because a self-hosted daemon only knows whether it HAS a bridge after its domain and credential
// are in place, which is after the handlers are built.
func (h *IdentityHandler) SetBridgeResolver(f BridgeResolver) { h.resolveBridge = f }

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
	log logr.Logger,
) *IdentityHandler {
	return &IdentityHandler{
		lookup:        lookup,
		verifyManaged: verifyManaged,
		requiresOnion: requiresOnion,
		relayHints:    relayHints,
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
		// Not a DMCN identity. It may still be reachable as ordinary email, through this
		// domain's bridge — so answer with the bridge's key and address rather than a flat
		// "not found". The client then seals to the bridge and STOREs there exactly as it
		// would for any recipient; the bridge reads the real destination out of the decrypted
		// message and hands it to SMTP.
		//
		// The recipient's own domain is irrelevant here: gmail.com has no _dmcn record and
		// never will. What is resolved is OUR bridge, and it is credential-verified before
		// anything is sealed to it — which matters, because unlike a relay a bridge sees the
		// plaintext.
		if h.legacyLookup(w, r, address) {
			return
		}
		h.log.Error("identity lookup failed", logr.M("error", err.Error()), logr.M("address", address))
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}

	// verified_tier is the cryptographically verified tier (vs the self-claimed
	// verification_tier). We only run the full DAR/DNS/removal verification when
	// the record actually carries an address credential — otherwise it can't exceed
	// its self-claimed tier and the extra fleet/DNS round-trips are pointless.
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":               rec.Address,
		"ed25519_pub":           base64.StdEncoding.EncodeToString(rec.Ed25519Public),
		"x25519_pub":            base64.StdEncoding.EncodeToString(rec.X25519Public[:]),
		"fingerprint":           rec.Fingerprint(),
		"verification_tier":     int(rec.VerificationTier),
		"verified_tier":         verifiedTier,
		"identity_unverifiable": unverifiable,
		"require_onion":         requireOnion,
	})
}

// legacyLookup answers a lookup for an address that is not a DMCN identity, by pointing the client
// at this domain's outbound bridge. It reports whether it wrote a response.
//
// The reply deliberately mirrors a normal lookup — an x25519 key to seal to and relay hints to
// STORE to — so the compose path needs no special case. What differs is `legacy: true`, which the
// client uses to say plainly that this message leaves the network: it is end-to-end encrypted to
// the bridge, and ordinary email from there on.
func (h *IdentityHandler) legacyLookup(w http.ResponseWriter, r *http.Request, address string) bool {
	if h.resolveBridge == nil {
		return false // no bridge on this deployment; a legacy address is simply unreachable
	}
	xPub, ma, err := h.resolveBridge(r.Context())
	if err != nil {
		h.log.Warn("no outbound bridge for a legacy recipient",
			logr.M("address", address), logr.M("error", err.Error()))
		return false
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"address":     address,
		"legacy":      true,
		"x25519_pub":  base64.StdEncoding.EncodeToString(xPub[:]),
		"relay_hints": []string{ma},
		// No ed25519_pub: there is no DMCN identity behind a legacy address, and inventing one
		// would let the UI imply a verified sender where none exists.
		"verified_tier": int(identity.TierUnverified),
	})
	return true
}
