package identity

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Address-choice rules. These constrain what a user may CHOOSE as their own
// address at registration. They are intentionally stricter than validateAddress
// (which only checks the local@domain shape) and are applied at the user-facing
// choke points — web HandleRegister and the identity CLI — NOT in the generic
// record construction/parse path. Internal/ephemeral identities (device, pairing,
// bridge) build records directly via NewIdentityRecord and must stay unaffected.
var (
	// ErrLocalPartFormat is returned when the local-part violates the character,
	// length, or shape rules for a user-chosen address.
	ErrLocalPartFormat = errors.New("identity: invalid local part")
	// ErrLocalPartIsPublicKey is returned when the local-part is shaped like a DMCN
	// public key (or key fingerprint) — reserved so a hex key can never be claimed as
	// an address and mistaken for a key-addressed identity.
	ErrLocalPartIsPublicKey = errors.New("identity: local part must not be a public key")
)

// localPartRe requires the local-part to start and end with an alphanumeric and to
// sandwich every separator (-, ., _) between alphanumeric runs — so it can never
// start/end with a separator or use two separators consecutively. A flat class
// (^[a-z0-9][-._a-z0-9]{0,63}$) cannot express "no adjacent separators", and RE2 has
// no lookahead, so the 1–64 length bound is checked separately in ValidateLocalPart.
var localPartRe = regexp.MustCompile(`^[a-z0-9]+([-._][a-z0-9]+)*$`)

// hexOnlyRe matches a string composed solely of lowercase hex digits.
var hexOnlyRe = regexp.MustCompile(`^[0-9a-f]+$`)

const (
	// localPartMin/Max bound the local-part length. Max matches the RFC 5321 email
	// local-part limit for bridge/legacy-email interop. One character is a valid
	// address (me@example.me); a provider that wants short names held back on a
	// domain it shares between customers enforces that itself.
	localPartMin = 1
	localPartMax = 64
	// A 32-byte Ed25519/X25519 key hex-encodes to 64 chars; the identity fingerprint
	// (first 20 bytes of SHA-256, see fingerprintOf) hex-encodes to 40 chars. A
	// lowercase-hex local-part of either length is reserved.
	hexPublicKeyLen   = 64
	hexFingerprintLen = 40
)

// ValidateLocalPart enforces the address-choice rules on a local-part:
//   - length 1–64
//   - lowercase, starts and ends with [a-z0-9], only [-._a-z0-9] otherwise, no
//     consecutive separators
//   - not shaped like a DMCN public key (all-lowercase-hex of length 40 or 64)
func ValidateLocalPart(local string) error {
	if len(local) < localPartMin || len(local) > localPartMax {
		return fmt.Errorf("%w: %q must be %d–%d characters", ErrLocalPartFormat, local, localPartMin, localPartMax)
	}
	if !localPartRe.MatchString(local) {
		return fmt.Errorf("%w: %q must be lowercase, start and end with a letter or digit, "+
			"use only a–z, 0–9, dot, dash, underscore, and not repeat dot/dash/underscore", ErrLocalPartFormat, local)
	}
	if (len(local) == hexPublicKeyLen || len(local) == hexFingerprintLen) && hexOnlyRe.MatchString(local) {
		return fmt.Errorf("%w: %q", ErrLocalPartIsPublicKey, local)
	}
	return nil
}

// ValidateChosenAddress validates a full local@domain address that a user is
// choosing to register: strict local-part rules plus the basic domain check.
func ValidateChosenAddress(address string) error {
	parts := strings.SplitN(address, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: %q", ErrInvalidAddress, address)
	}
	if err := ValidateLocalPart(parts[0]); err != nil {
		return err
	}
	if err := validateDomain(parts[1]); err != nil {
		return err
	}
	return nil
}
