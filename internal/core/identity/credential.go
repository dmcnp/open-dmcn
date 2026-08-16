package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// Roles a Credential may carry. Roles combine (a user device is ["address","client"]).
const (
	RoleAuthority    = "authority"
	RoleSubAuthority = "sub-authority"
	RoleNode         = "node"
	RoleBridge       = "bridge"
	RoleClient       = "client"
	RoleAddress      = "address"
	// RoleRouting marks an operator-signed mailbox-routing credential. It carries the
	// authoritative RelayHints for an address; the domain authority/sub-authority issues
	// it (and re-issues it on rebalance) so routing is operator-owned, not owner-signed.
	RoleRouting = "routing"
	// GrantDelegate, in a Credential's Grants, additionally permits issuing credentials
	// that themselves carry Grants (i.e. creating sub-authorities). Without it a subject
	// may only issue plain leaves for the roles it was granted.
	GrantDelegate = "grant"
	// GrantRouting / GrantAddress are the issuance grants for the routing/address roles.
	// A grant string equals the role string it authorises issuing, so these alias the role
	// constants; they exist to read intent at op-gating / issuance sites.
	GrantRouting = RoleRouting
	GrantAddress = RoleAddress
)

// allGrants is the grant universe of the DNS-anchored root: the leaf-role issuance grants
// plus the delegation capability. It is NOT a credential's role set — no
// credential ever carries every role. "authority"/"sub-authority" are intentionally
// absent: creating authorities is governed by GrantDelegate (see authorizes), and no
// credential carries them in its Grants.
var allGrants = []string{RoleNode, RoleBridge, RoleClient, RoleAddress, RoleRouting, GrantDelegate}

// rootGrants returns the implicit grants of the DNS-anchored root (a copy of allGrants).
func rootGrants() []string { return append([]string{}, allGrants...) }

// maxChainDepth bounds credential-chain walks (defence against a cyclic/abusive DAR).
const maxChainDepth = 8

// credSkew tolerates small clock differences on validity-window checks.
const credSkew = 2 * time.Minute

var (
	// ErrCredentialSignature is returned when a credential's issuer signature is invalid.
	ErrCredentialSignature = errors.New("identity: credential signature invalid")
	// ErrCredentialBlocked is returned when a credential's subject or an issuer in its
	// chain is blocked at the relevant time.
	ErrCredentialBlocked = errors.New("identity: credential blocked")
)

// Credential is the unified DMCN membership credential — an authority's countersignature
// over a subject public key, binding it to a domain with roles, the roles it may itself
// issue (Grants), and verifiable Attributes. See the Credential PKI plan.
type Credential struct {
	Version    uint32
	Subject    ed25519.PublicKey
	Domain     string
	Address    string
	Roles      []string
	Grants     []string
	Attributes map[string]string
	IssuedAt   time.Time
	NotAfter   time.Time // zero = never expires
	// EffectiveFrom is an optional not-before: the credential is valid only from this
	// time (zero = no constraint, effective immediately). Validity window is
	// [EffectiveFrom, NotAfter]. Covered by the issuer signature. Lets a credential be
	// forward-dated (e.g. the suspended access assertion that begins when the open one ends).
	EffectiveFrom time.Time
	Scope         string // authority creds: subdomain scope ("" = whole domain)
	IssuerPub     ed25519.PublicKey
	Signature     []byte
	// RelayHints carries the authoritative mailbox relay hints for a role "routing"
	// credential (empty otherwise). Covered by the issuer signature.
	// Extension payloads (e.g. the product's send-rate schedule) ride the Attributes map
	// under "ext."-prefixed keys — signature-covered without core schema coupling.
	RelayHints []string
}

// HasRole reports whether the credential carries role r.
func (c *Credential) HasRole(r string) bool { return contains(c.Roles, r) }

// HasGrant reports whether the credential carries grant g (an action it may perform).
func (c *Credential) HasGrant(g string) bool { return contains(c.Grants, g) }

// CoversDomain reports whether this credential's domain authority extends to target —
// target is the credential's Domain or a subdomain of it. Used to scope operator/relay ops
// to the domain the credential is actually for, so a grant issued for one domain cannot
// authorize an action on another. An empty target is never covered (fail closed).
func (c *Credential) CoversDomain(target string) bool {
	return target != "" && scopeCovers(c.Domain, target)
}

// signableBytes is the deterministic serialisation the issuer signs (all but Signature).
func (c *Credential) signableBytes() ([]byte, error) {
	pb := c.ToProto()
	pb.Signature = nil
	return protoMarshal(pb)
}

// Sign sets Signature using the issuer key (the issuer must hold the matching
// IssuerPub). Sets IssuerPub from the signer.
func (c *Credential) Sign(issuer *IdentityKeyPair) error {
	c.IssuerPub = issuer.Ed25519Public
	data, err := c.signableBytes()
	if err != nil {
		return fmt.Errorf("identity: credential sign: %w", err)
	}
	sig, err := signCtx(issuer.Ed25519Private, ctxCredential, data)
	if err != nil {
		return fmt.Errorf("identity: credential sign: %w", err)
	}
	c.Signature = sig
	return nil
}

// VerifySignature checks the issuer signature against IssuerPub only. It does NOT
// establish that IssuerPub is authorised — that is VerifyCredential's job.
func (c *Credential) VerifySignature() error {
	if len(c.IssuerPub) != ed25519.PublicKeySize {
		return ErrCredentialSignature
	}
	data, err := c.signableBytes()
	if err != nil {
		return err
	}
	if err := verifyCtx(c.IssuerPub, ctxCredential, data, c.Signature); err != nil {
		return ErrCredentialSignature
	}
	return nil
}

// ToProto converts the credential to protobuf.
func (c *Credential) ToProto() *dmcnpb.Credential {
	pb := &dmcnpb.Credential{
		Version:    c.Version,
		Subject:    c.Subject,
		Domain:     c.Domain,
		Address:    c.Address,
		Roles:      c.Roles,
		Grants:     c.Grants,
		Attributes: c.Attributes,
		IssuedAt:   c.IssuedAt.Unix(),
		Scope:      c.Scope,
		IssuerPub:  c.IssuerPub,
		Signature:  c.Signature,
		RelayHints: c.RelayHints,
	}
	if !c.NotAfter.IsZero() {
		pb.NotAfter = c.NotAfter.Unix()
	}
	if !c.EffectiveFrom.IsZero() {
		pb.EffectiveFrom = c.EffectiveFrom.Unix()
	}
	return pb
}

// CredentialFromProto builds a Credential from protobuf.
func CredentialFromProto(pb *dmcnpb.Credential) (*Credential, error) {
	if pb == nil {
		return nil, errors.New("identity: nil credential protobuf")
	}
	c := &Credential{
		Version:    pb.Version,
		Subject:    pb.Subject,
		Domain:     pb.Domain,
		Address:    pb.Address,
		Roles:      pb.Roles,
		Grants:     pb.Grants,
		Attributes: pb.Attributes,
		IssuedAt:   time.Unix(pb.IssuedAt, 0).UTC(),
		Scope:      pb.Scope,
		IssuerPub:  pb.IssuerPub,
		Signature:  pb.Signature,
		RelayHints: pb.RelayHints,
	}
	if pb.NotAfter != 0 {
		c.NotAfter = time.Unix(pb.NotAfter, 0).UTC()
	}
	if pb.EffectiveFrom != 0 {
		c.EffectiveFrom = time.Unix(pb.EffectiveFrom, 0).UTC()
	}
	return c, nil
}

// CredentialFromProtoBytes deserialises a credential from raw bytes.
func CredentialFromProtoBytes(data []byte) (*Credential, error) {
	pb := &dmcnpb.Credential{}
	if err := proto.Unmarshal(data, pb); err != nil {
		return nil, fmt.Errorf("identity: credential unmarshal: %w", err)
	}
	return CredentialFromProto(pb)
}

// VerifyCredential fully validates a leaf credential against a domain's DAR (already
// fetched + DNS-anchored by the caller) and its blocklist (may be nil) at time `now`:
//   - the issuer signature is valid;
//   - the issuer chain resolves to the DNS-anchored root via the DAR's authority creds;
//   - each issuer was authorised at the credential's IssuedAt and grants what it issued
//     (monotone Roles/Grants/scope — no escalation);
//   - no subject/issuer in the chain is blocked for the credential's IssuedAt;
//   - the credential is not past an optional NotAfter.
//
// It does NOT check role-appropriateness for a given use (callers do, e.g. "needs node")
// nor multiaddr attributes (the join handshake does).
func VerifyCredential(leaf *Credential, dar *DomainAuthorityRecord, blocks *CredentialBlockList, now time.Time) error {
	if dar == nil {
		return errors.New("identity: verify credential: nil DAR")
	}
	return verifyChain(leaf, dar, blocks, now, 0)
}

// VerifyFleetCredential validates a fleet credential that chains DIRECTLY to the fleet
// operator root — config-anchored by the operator public key (`DMCN_*_OPERATOR_PUBKEY`),
// with NO DAR and NO chain: the operator signs fleet credentials directly, offline. It is
// valid iff the issuer signature is valid, the issuer IS the operator root, it is not past
// NotAfter, and its roles/grants are within the operator root's universe (monotone, with the
// delegation capability still gating grant-bearing creds). Revocation is config-side (a
// denylist of subject keys), enforced by the caller — there is no signed blocklist here.
func VerifyFleetCredential(c *Credential, operatorPub ed25519.PublicKey, now time.Time) error {
	if len(operatorPub) != ed25519.PublicKeySize {
		return errors.New("identity: verify fleet credential: no operator root key configured")
	}
	if err := c.VerifySignature(); err != nil {
		return err
	}
	if !bytes.Equal(c.IssuerPub, operatorPub) {
		return errors.New("identity: fleet credential not signed by the operator root")
	}
	if !c.NotAfter.IsZero() && now.After(c.NotAfter.Add(credSkew)) {
		return fmt.Errorf("identity: fleet credential expired at %s", c.NotAfter)
	}
	if !c.EffectiveFrom.IsZero() && now.Add(credSkew).Before(c.EffectiveFrom) {
		return fmt.Errorf("identity: fleet credential not yet effective until %s", c.EffectiveFrom)
	}
	// The operator root holds the full grant universe; this enforces monotonicity (no
	// unknown roles/grants) and the GrantDelegate gate for any grant-bearing fleet cred.
	return authorizes(rootGrants(), "", c.Domain, c)
}

func verifyChain(c *Credential, dar *DomainAuthorityRecord, blocks *CredentialBlockList, now time.Time, depth int) error {
	if depth > maxChainDepth {
		return errors.New("identity: credential chain too deep")
	}
	if err := c.VerifySignature(); err != nil {
		return err
	}
	if !c.NotAfter.IsZero() && now.After(c.NotAfter.Add(credSkew)) {
		return fmt.Errorf("identity: credential expired at %s", c.NotAfter)
	}
	if !c.EffectiveFrom.IsZero() && now.Add(credSkew).Before(c.EffectiveFrom) {
		return fmt.Errorf("identity: credential not yet effective until %s", c.EffectiveFrom)
	}
	if blocks.Blocked(c.Subject, c.IssuedAt) || blocks.Blocked(c.IssuerPub, c.IssuedAt) {
		return ErrCredentialBlocked
	}

	// Resolve the issuer at the credential's IssuedAt: the DNS-anchored root, or an
	// authority credential in the DAR (which is itself verified recursively).
	if rk, ok := dar.RootKeyAt(c.IssuedAt); ok && bytes.Equal(rk, c.IssuerPub) {
		return authorizes(rootGrants(), "", dar.Domain, c)
	}
	issuer := dar.ResolveAuthority(c.IssuerPub)
	if issuer == nil {
		return fmt.Errorf("identity: credential issuer not authorised by domain %s", dar.Domain)
	}
	// Authority to issue comes from the issuer's grants (checked by authorizes below), not
	// from a "sub-authority" role: any DAR-enrolled credential whose grants cover the leaf
	// (and that holds GrantDelegate for grant-bearing leaves) may issue.
	// The issuer authority must have existed before it signed.
	if c.IssuedAt.Add(credSkew).Before(issuer.IssuedAt) {
		return errors.New("identity: credential predates its issuer authority")
	}
	if err := verifyChain(issuer, dar, blocks, now, depth+1); err != nil {
		return err
	}
	return authorizes(issuer.Grants, issuer.Scope, dar.Domain, c)
}

// authorizes enforces the monotone capability calculus: the issuer (with issuerGrants +
// issuerScope, governing `domain`) may issue credential c. Authority roles
// (authority/sub-authority) and any Grants are gated by the delegation capability
// (`grant`); plain leaf roles must each be in the issuer's Grants.
func authorizes(issuerGrants []string, issuerScope, domain string, c *Credential) error {
	isAuthority := len(c.Grants) > 0
	for _, r := range c.Roles {
		if r == RoleAuthority || r == RoleSubAuthority {
			isAuthority = true // gated by `grant` below, not by Grants membership
			continue
		}
		if !contains(issuerGrants, r) {
			return fmt.Errorf("identity: issuer may not grant role %q", r)
		}
	}
	// A grants-bearing / authority credential may only be issued by a delegator.
	if isAuthority && !contains(issuerGrants, GrantDelegate) {
		return errors.New("identity: issuer lacks the 'grant' capability to create authorities")
	}
	// Can't delegate more than you hold.
	for _, g := range c.Grants {
		if !contains(issuerGrants, g) {
			return fmt.Errorf("identity: issuer may not delegate grant %q", g)
		}
	}
	// Scope only narrows: the credential's target domain must be within the issuer scope.
	target := c.Domain
	if c.Address != "" {
		target = domainverify.DomainOf(c.Address)
	}
	if issuerScope != "" && !scopeCovers(issuerScope, target) {
		return fmt.Errorf("identity: issuer scope %q does not cover %q", issuerScope, target)
	}
	if !scopeCovers(domain, target) {
		return fmt.Errorf("identity: credential domain %q outside %q", target, domain)
	}
	return nil
}

// scopeCovers reports whether `target` is `scope` or a subdomain of it.
func scopeCovers(scope, target string) bool {
	scope, target = strings.ToLower(scope), strings.ToLower(target)
	return target == scope || strings.HasSuffix(target, "."+scope)
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
