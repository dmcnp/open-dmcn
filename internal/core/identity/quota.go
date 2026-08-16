package identity

import (
	"crypto/ed25519"
	"strconv"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
)

// QuotaAttr is the Credential.Attributes key holding an account's personal-storage
// allowance (decimal bytes) in a RoleQuota credential.
const QuotaAttr = "quota_bytes"

// NewQuotaCredential builds an unsigned RoleQuota credential raising address's
// personal-storage allowance to quotaBytes. ownerKey is the address owner's Ed25519 key
// (the Subject), so a relay can bind the quota to that account and no other. notAfter zero
// means no expiry (else the subscription-period end, after which the cap reverts).
//
// Sign it with a domain key holding the 'quota' grant — the web's ONLINE issuer key (the
// same key it signs routing/address credentials with) on payment, or an offline domain
// authority via the CLI. It is verified against the domain DAR like any other credential;
// the fleet operator key is never involved, so it never needs to live on the web.
func NewQuotaCredential(ownerKey ed25519.PublicKey, address string, quotaBytes uint64, at, notAfter time.Time) *Credential {
	return &Credential{
		Version:    1,
		Subject:    ownerKey,
		Domain:     domainverify.DomainOf(address),
		Address:    address,
		Roles:      []string{RoleQuota},
		Attributes: map[string]string{QuotaAttr: strconv.FormatUint(quotaBytes, 10)},
		IssuedAt:   at.UTC(),
		NotAfter:   notAfter,
	}
}

// QuotaBytesOf returns the allowance encoded in a RoleQuota credential's attributes, or 0
// if absent/unparseable.
func QuotaBytesOf(c *Credential) uint64 {
	if c == nil || c.Attributes == nil {
		return 0
	}
	n, err := strconv.ParseUint(c.Attributes[QuotaAttr], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// MarshalCredential serializes a signed credential to bytes (the SetQuota wire form).
// CredentialFromProtoBytes is the inverse.
func MarshalCredential(c *Credential) ([]byte, error) {
	return protoMarshal(c.ToProto())
}
