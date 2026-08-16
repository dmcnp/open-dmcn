package identity

import (
	"crypto/ed25519"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
)

// AccessModeAttr is the Credential.Attributes key on a RoleAccess credential naming which
// assertion it is — "open" or "suspended". It is the assertion's intrinsic type, NOT a
// runtime override: each assertion asserts exactly one mode over its own [EffectiveFrom,
// NotAfter] window.
const AccessModeAttr = "access_mode"

// Access modes the relay enforces per account (derived from the installed assertions):
//   - AccessOpen      — FETCH ok, STORE-inbound ok.
//   - AccessSuspended — FETCH denied, STORE-inbound still accepted (grace).
//   - AccessClosed    — FETCH denied, STORE-inbound rejected (terminal; reversible by
//     installing a fresh open assertion — permanent retirement is the DAR tombstone).
//
// Only "open" and "suspended" are ever issued as assertions; "closed" is the terminal the
// relay DERIVES when assertions exist but none is currently in effect (all windows elapsed).
const (
	AccessOpen      = "open"
	AccessSuspended = "suspended"
	AccessClosed    = "closed"
)

// NewAccessCredential builds an unsigned RoleAccess assertion for address, of the given mode
// ("open" or "suspended"), effective over [effectiveFrom, notAfter]. ownerKey is the address
// owner's Ed25519 key (the Subject), so a relay binds the entitlement to that account and no
// other. A zero effectiveFrom means "effective immediately"; a zero notAfter means the window
// never ends on its own (stays in this mode). Sign it with a domain key holding the 'access'
// grant (the b2c online issuer key), like a quota credential.
func NewAccessCredential(ownerKey ed25519.PublicKey, address, mode string, effectiveFrom, notAfter, at time.Time) *Credential {
	return &Credential{
		Version:       1,
		Subject:       ownerKey,
		Domain:        domainverify.DomainOf(address),
		Address:       address,
		Roles:         []string{RoleAccess},
		Attributes:    map[string]string{AccessModeAttr: mode},
		IssuedAt:      at.UTC(),
		EffectiveFrom: effectiveFrom,
		NotAfter:      notAfter,
	}
}

// AccessModeOf returns the mode a RoleAccess assertion carries ("open"/"suspended"), or "" if
// the credential is nil or missing the attribute.
func AccessModeOf(c *Credential) string {
	if c == nil || c.Attributes == nil {
		return ""
	}
	return c.Attributes[AccessModeAttr]
}

// inEffect reports whether a credential's [EffectiveFrom, NotAfter] window contains now
// (zero bounds = unbounded on that side).
func (c *Credential) inEffect(now time.Time) bool {
	if c == nil {
		return false
	}
	if !c.EffectiveFrom.IsZero() && now.Before(c.EffectiveFrom) {
		return false
	}
	if !c.NotAfter.IsZero() && !now.Before(c.NotAfter) {
		return false
	}
	return true
}

// DeriveAccessMode computes an account's current access mode from its installed assertions,
// as of now. openCred/suspCred are the stored "open" and "suspended" assertions (either may
// be nil). The rule (open wins any overlap):
//   - both nil          → AccessOpen  (default-open: unmanaged / self-hosted / user-owned)
//   - open in effect    → AccessOpen
//   - else suspended in effect → AccessSuspended
//   - else (assertions exist but none in effect — every window elapsed) → AccessClosed
func DeriveAccessMode(openCred, suspCred *Credential, now time.Time) string {
	if openCred == nil && suspCred == nil {
		return AccessOpen
	}
	if openCred.inEffect(now) {
		return AccessOpen
	}
	if suspCred.inEffect(now) {
		return AccessSuspended
	}
	return AccessClosed
}
