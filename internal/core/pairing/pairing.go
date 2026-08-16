// Package pairing provides the throwaway ephemeral-address helpers used by the
// resolver and the PutRecord path to recognise non-routable pairing addresses.
//
// NOTE (open-dmcn reference implementation): the full device-pairing / key-clone
// flow (CloneRequest/CloneResponse control payloads) is a PRODUCT extension and
// is intentionally omitted here. Only the ephemeral-address predicate + record
// helpers remain, so `internal/node/resolver.go` and `internal/relay/putrecord.go`
// compile and behave correctly (a reference node never mints pairing addresses,
// so those branches are inert).
package pairing

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

const (
	// EphemeralDomain is the domain used for throwaway ephemeral pairing
	// addresses. They are never real, registered, or routable as email.
	EphemeralDomain = "pairing.local"

	// EphemeralTTL is how long the ephemeral identity record stays valid. It is
	// single-use; this just bounds how long an abandoned record lingers.
	EphemeralTTL = 15 * time.Minute
)

// IsEphemeralAddress reports whether addr is a throwaway device-pairing address
// on the reserved EphemeralDomain. These addresses are never real, registered, or
// routable as email, so callers may treat their records as powerless throwaways.
func IsEphemeralAddress(addr string) bool {
	return strings.HasSuffix(addr, "@"+EphemeralDomain)
}

// EphemeralAddress returns a fresh, unique throwaway address for an ephemeral
// pairing identity.
func EphemeralAddress() (string, error) {
	b, err := crypto.RandomBytes(8)
	if err != nil {
		return "", fmt.Errorf("pairing: ephemeral address: %w", err)
	}
	return "pair-" + hex.EncodeToString(b) + "@" + EphemeralDomain, nil
}

// NewEphemeralRecord builds a self-signed, tier-0 IdentityRecord for an ephemeral
// pairing identity, with the given relay as its only hint and a short expiry.
func NewEphemeralRecord(address string, kp *identity.IdentityKeyPair, relayHint string, now time.Time) (*identity.IdentityRecord, error) {
	rec, err := identity.NewIdentityRecord(address, kp)
	if err != nil {
		return nil, fmt.Errorf("pairing: ephemeral record: %w", err)
	}
	rec.RelayHints = []string{relayHint}
	rec.ExpiresAt = now.Add(EphemeralTTL).UTC()
	if err := rec.Sign(kp); err != nil {
		return nil, fmt.Errorf("pairing: sign ephemeral record: %w", err)
	}
	return rec, nil
}
