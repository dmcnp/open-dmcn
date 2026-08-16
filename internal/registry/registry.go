// Package registry is the DMCN identity verification service. Historically it wrapped a libp2p
// Kademlia DHT for record storage; that DHT has been removed — records are now served
// authoritatively by each domain's fleet and fetched via the resolver (see internal/node). This
// package retains the reader-side verification layer (credential/DAR/routing checks + DNS anchoring)
// and reads every record it needs through an injected, DHT-free RecordSource.
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// DNSVerifier checks that _dmcn.<domain> publishes a verification record carrying
// the given fingerprint. It matches domainverify.Verify and is injectable for
// tests.
type DNSVerifier func(ctx context.Context, domain, fingerprint string) error

var (
	// ErrNotFound is returned when a record is not available from the source.
	ErrNotFound = errors.New("registry: identity not found")
	// ErrInvalidRecord is returned when a record fails validation.
	ErrInvalidRecord = errors.New("registry: invalid identity record")
	// ErrPendingCountersign is returned by AddressUsable when an address on a
	// require-countersign domain lacks a valid domain address credential (the name
	// is historical; the required artifact is the RoleAddress credential).
	ErrPendingCountersign = errors.New("registry: address pending domain countersignature")
)

// darCacheTTL bounds how long a Domain Authority Record (or its absence) is cached
// for the AddressUsable policy check on the hot FETCH path.
const darCacheTTL = 30 * time.Second

type darCacheEntry struct {
	dar *identity.DomainAuthorityRecord // nil = no DAR for this domain (cached negative)
	at  time.Time
}

// Registry is the DHT-free identity verification service. It fetches records through source and
// caches DARs for the hot FETCH-path policy checks.
type Registry struct {
	dnsVerify DNSVerifier
	darCache  sync.Map      // domain -> *darCacheEntry (policy lookups on the FETCH path)
	source    *RecordSource // record source (fleet resolver + local RecordStore)
}

// RecordSource supplies self-authenticating records from the fleet resolver + the node's local
// RecordStore. Every registry Lookup* (and thus every verification path that fetches a
// DAR/removal/blocklist/descriptor) reads through it. Any field may be nil (that record kind is then
// unavailable — Lookup returns ErrNotFound / a blocklist reads as absent, fail-open).
type RecordSource struct {
	Identity   func(ctx context.Context, address string) (*identity.IdentityRecord, error)
	DAR        func(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error)
	Removal    func(ctx context.Context, address string) (*identity.AddressRemovalRecord, error)
	Blocklist  func(ctx context.Context, domain string) (*identity.CredentialBlockList, error)
	Descriptor func(ctx context.Context, peerID string) (*identity.RelayDescriptor, error)
}

// SetRecordSource installs the record source (called by the node once it can build the
// resolver-backed closures). Safe to call once at startup before the registry serves lookups.
func (r *Registry) SetRecordSource(src *RecordSource) { r.source = src }

// Option configures a Registry.
type Option func(*options)

type options struct {
	dnsVerify DNSVerifier
}

// WithDNSVerifier overrides the DNS verifier used to anchor Domain Authority
// Records. Defaults to domainverify.Verify. Tests inject a fake.
func WithDNSVerifier(v DNSVerifier) Option {
	return func(o *options) {
		o.dnsVerify = v
	}
}

// New creates a verification-service Registry. Records are served through the RecordSource the node
// installs via SetRecordSource; New itself allocates no network resources.
func New(opts ...Option) *Registry {
	cfg := &options{dnsVerify: domainverify.Verify}
	for _, o := range opts {
		o(cfg)
	}
	return &Registry{dnsVerify: cfg.dnsVerify}
}

// Lookup returns an address's IdentityRecord from the source (self-signature already verified by the
// source), or ErrNotFound when no source is installed or the record is absent.
func (r *Registry) Lookup(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	if r.source == nil || r.source.Identity == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, address)
	}
	return r.source.Identity(ctx, address)
}

// LookupDomainAuthority returns a domain's DAR from the source. Only a definitive "no DAR" maps to
// ErrNotFound; other errors (can't reach the fleet) pass through so fail-closed callers can tell
// "no DAR" from "can't know".
func (r *Registry) LookupDomainAuthority(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error) {
	if r.source == nil || r.source.DAR == nil {
		return nil, fmt.Errorf("%w: DAR for %s", ErrNotFound, domain)
	}
	return r.source.DAR(ctx, domain)
}

// LookupAddressRemoval returns an address's removal tombstone, or ErrNotFound if never offboarded.
// The caller verifies the root signature against the DAR.
func (r *Registry) LookupAddressRemoval(ctx context.Context, address string) (*identity.AddressRemovalRecord, error) {
	if r.source == nil || r.source.Removal == nil {
		return nil, fmt.Errorf("%w: removal for %s", ErrNotFound, address)
	}
	rm, err := r.source.Removal(ctx, address)
	if err != nil {
		return nil, err
	}
	if rm == nil {
		return nil, fmt.Errorf("%w: removal for %s", ErrNotFound, address)
	}
	return rm, nil
}

// LookupCredentialBlockList returns a domain's root-signed blocklist, or (nil, nil) when none is
// published / the source can't verify one (fail-open — a non-propagated block must not cause
// outages). The source is responsible for verifying the root signature.
func (r *Registry) LookupCredentialBlockList(ctx context.Context, domain string) (*identity.CredentialBlockList, error) {
	if r.source == nil || r.source.Blocklist == nil {
		return nil, nil
	}
	bl, err := r.source.Blocklist(ctx, domain)
	if err != nil {
		return nil, nil
	}
	return bl, nil
}

// LookupRelayDescriptor returns a relay's onion descriptor from the source (self-anchored signature
// already verified by the source), or ErrNotFound when absent.
func (r *Registry) LookupRelayDescriptor(ctx context.Context, peerID string) (*identity.RelayDescriptor, error) {
	if r.source == nil || r.source.Descriptor == nil {
		return nil, fmt.Errorf("%w: relay descriptor for %s", ErrNotFound, peerID)
	}
	desc, err := r.source.Descriptor(ctx, peerID)
	if err != nil {
		return nil, err
	}
	if desc == nil {
		return nil, fmt.Errorf("%w: relay descriptor for %s", ErrNotFound, peerID)
	}
	return desc, nil
}

// VerifyManagedIdentity returns the effective verification tier for a record. It validates the owner
// self-signature; verifies the operator routing credential (RoleRouting) when present — its issuer
// must chain to the domain's DNS-proven DAR and its RelayHints must match the record; and, when an
// address credential (RoleAddress) is present, anchors that to the DAR too (issuer authorized, cred
// verifies, binding not tombstoned by a root-signed removal). A record without an address credential
// returns its self-claimed tier. Any failure returns TierUnverified.
func (r *Registry) VerifyManagedIdentity(ctx context.Context, rec *identity.IdentityRecord) (identity.VerificationTier, error) {
	if err := rec.Verify(); err != nil {
		return identity.TierUnverified, fmt.Errorf("registry: self-signature: %w", err)
	}
	domain := domainverify.DomainOf(rec.Address)

	// Credential PKI: the operator's routing credential. RelayHints is operator-owned and
	// excluded from the owner self-signature, so its trust comes from this credential.
	// Verified independently of the address credential (it may be re-issued on rebalance).
	if rec.HasRoutingCredential() {
		rc := rec.RoutingCredential
		if rc.Domain != domain || rc.Address != rec.Address || !rc.HasRole(identity.RoleRouting) || !bytes.Equal(rc.Subject, rec.Ed25519Public) {
			return identity.TierUnverified, errors.New("registry: routing credential does not match record")
		}
		if !relayHintsEqual(rec.RelayHints, rc.RelayHints) {
			return identity.TierUnverified, errors.New("registry: relay hints do not match routing credential")
		}
		if err := r.VerifyCredential(ctx, rc); err != nil {
			return identity.TierUnverified, fmt.Errorf("registry: routing credential: %w", err)
		}
	}

	// Credential PKI: the domain's address credential. The user self-signature above is the
	// other half of the dual binding (user controls the key); this credential is the
	// domain's attestation that the user holds the address.
	if !rec.HasAddressCredential() {
		return rec.VerificationTier, nil
	}
	cred := rec.AddressCredential
	if cred.Domain != domain || cred.Address != rec.Address || !cred.HasRole(identity.RoleAddress) || !bytes.Equal(cred.Subject, rec.Ed25519Public) {
		return identity.TierUnverified, errors.New("registry: address credential does not match record")
	}
	if err := r.VerifyCredential(ctx, cred); err != nil {
		return identity.TierUnverified, fmt.Errorf("registry: address credential: %w", err)
	}
	// A root-signed removal tombstone still invalidates the binding.
	if rm, rerr := r.LookupAddressRemoval(ctx, rec.Address); rerr == nil {
		if dar := r.cachedLookupDAR(ctx, domain); dar != nil && removalIsRootSigned(dar, rm) {
			if _, removed := rm.Removed(rec.Ed25519Public); removed {
				return identity.TierUnverified, errors.New("registry: binding removed by domain")
			}
		}
	}
	return identity.TierDomainDNS, nil
}

// relayHintsEqual reports whether two ordered relay-hint lists are identical.
func relayHintsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyCredential validates a presented Credential (Credential PKI) against its domain's
// DNS-anchored DAR and blocklist. A nil return means the credential's issuer chain is valid and
// unrevoked — the CALLER must additionally check that cred.Subject matches the presenting peer's
// proven peer ID and any multiaddr attribute.
func (r *Registry) VerifyCredential(ctx context.Context, cred *identity.Credential) error {
	if cred == nil {
		return errors.New("registry: nil credential")
	}
	dar := r.cachedLookupDAR(ctx, cred.Domain)
	if dar == nil {
		return fmt.Errorf("registry: no domain authority for %s", cred.Domain)
	}
	if err := dar.Verify(); err != nil {
		return fmt.Errorf("registry: DAR signature: %w", err)
	}
	if err := r.dnsVerify(ctx, cred.Domain, dar.Fingerprint()); err != nil {
		return fmt.Errorf("registry: DAR DNS anchor: %w", err)
	}
	blocks, _ := r.LookupCredentialBlockList(ctx, cred.Domain) // fail-open on miss
	return identity.VerifyCredential(cred, dar, blocks, time.Now())
}

// VerifyCredentialWithDAR validates a credential against a DAR supplied by the caller (bundled in the
// /dmcn/join or /dmcn/provision exchange) rather than one fetched from the fleet — so an inert,
// peerless node can verify a presented credential using only a direct DNS resolution of the DAR's
// _dmcn fingerprint. The blocklist is best-effort (fail-open). The caller still checks cred.Subject
// against the proven peer ID.
func (r *Registry) VerifyCredentialWithDAR(ctx context.Context, cred *identity.Credential, dar *identity.DomainAuthorityRecord) error {
	if cred == nil || dar == nil {
		return errors.New("registry: nil credential or DAR")
	}
	if dar.Domain != cred.Domain {
		return fmt.Errorf("registry: bundled DAR domain %q != credential domain %q", dar.Domain, cred.Domain)
	}
	if err := dar.Verify(); err != nil {
		return fmt.Errorf("registry: DAR signature: %w", err)
	}
	if err := r.dnsVerify(ctx, dar.Domain, dar.Fingerprint()); err != nil {
		return fmt.Errorf("registry: DAR DNS anchor: %w", err)
	}
	blocks, _ := r.LookupCredentialBlockList(ctx, cred.Domain) // fail-open on miss
	return identity.VerifyCredential(cred, dar, blocks, time.Now())
}

// cachedLookupDAR returns the domain's DAR (or nil if none), caching both hits and misses briefly so
// the AddressUsable FETCH-path check doesn't fetch per op.
func (r *Registry) cachedLookupDAR(ctx context.Context, domain string) *identity.DomainAuthorityRecord {
	if v, ok := r.darCache.Load(domain); ok {
		if e := v.(*darCacheEntry); time.Since(e.at) < darCacheTTL {
			return e.dar
		}
	}
	dar, err := r.LookupDomainAuthority(ctx, domain)
	if err != nil {
		dar = nil
	}
	r.darCache.Store(domain, &darCacheEntry{dar: dar, at: time.Now()})
	return dar
}

// AddressUsable reports whether an address is usable under its domain's policy: on a domain whose DAR
// sets PolicyRequireCountersign (or reserves the local-part), the record must carry a valid domain
// address credential (RoleAddress, Credential PKI), else ErrPendingCountersign. Domains without a DAR
// impose no requirement. This is the relay's FETCH-path validity gate (wired via WithFetchPolicy).
func (r *Registry) AddressUsable(ctx context.Context, rec *identity.IdentityRecord) error {
	domain := domainverify.DomainOf(rec.Address)
	dar := r.cachedLookupDAR(ctx, domain)
	if dar == nil {
		return nil
	}
	if !dar.RequiresCountersign() && !dar.ReservesLocalPart(domainverify.LocalPartOf(rec.Address)) {
		return nil
	}
	if !rec.HasAddressCredential() {
		return ErrPendingCountersign
	}
	tier, err := r.VerifyManagedIdentity(ctx, rec)
	if err != nil || tier != identity.TierDomainDNS {
		return ErrPendingCountersign
	}
	return nil
}

// VerifyRouting checks that a recipient record's RelayHints are safe to route mail to before a sender
// STOREs (or onion-delivers). RelayHints are operator-owned and excluded from the owner
// self-signature, so on a domain that publishes a DAR the hints MUST be backed by an operator routing
// credential that verifies against that DAR. On a domain with no DAR (open/unmanaged) the hints are
// inherently unverifiable, so this is best-effort and returns nil. Empty hints return nil.
func (r *Registry) VerifyRouting(ctx context.Context, rec *identity.IdentityRecord) error {
	if len(rec.RelayHints) == 0 {
		return nil
	}
	dar := r.cachedLookupDAR(ctx, domainverify.DomainOf(rec.Address))
	if dar == nil {
		return nil
	}
	if !rec.HasRoutingCredential() {
		return errors.New("registry: relay hints are not attested by an operator routing credential")
	}
	if _, err := r.VerifyManagedIdentity(ctx, rec); err != nil {
		return fmt.Errorf("registry: recipient routing credential invalid: %w", err)
	}
	return nil
}

// RequiresOnion reports the effective onion-delivery policy for an address: its own RequireOnion flag
// OR its domain's PolicyRequireOnion (stricter-wins).
func (r *Registry) RequiresOnion(ctx context.Context, rec *identity.IdentityRecord) bool {
	if rec.RequireOnion {
		return true
	}
	dar := r.cachedLookupDAR(ctx, domainverify.DomainOf(rec.Address))
	return dar != nil && dar.RequiresOnion()
}

// ReplicatesMailbox reports whether an address's domain declares mailbox replication (DAR
// PolicyReplicateMailbox). Domains without a DAR / without the bit ⇒ failover.
func (r *Registry) ReplicatesMailbox(ctx context.Context, address string) bool {
	dar := r.cachedLookupDAR(ctx, domainverify.DomainOf(address))
	return dar != nil && dar.ReplicatesMailbox()
}

// AllowsRequests reports whether a domain opens the self-service countersign request channel (DAR
// PolicyAllowRequests).
func (r *Registry) AllowsRequests(ctx context.Context, domain string) bool {
	dar := r.cachedLookupDAR(ctx, domain)
	return dar != nil && dar.AllowsRequests()
}

// AddressReserved reports whether an address's local-part is reserved on its domain (requires the
// domain authority's countersignature). Unmanaged domains (no DAR) reserve nothing.
func (r *Registry) AddressReserved(ctx context.Context, address string) bool {
	dar := r.cachedLookupDAR(ctx, domainverify.DomainOf(address))
	return dar != nil && dar.ReservesLocalPart(domainverify.LocalPartOf(address))
}

// removalIsRootSigned reports whether the removal record carries a valid signature from a domain root
// key the DAR vouches for (the key effective at its timestamp, or any timeline key).
func removalIsRootSigned(dar *identity.DomainAuthorityRecord, rm *identity.AddressRemovalRecord) bool {
	if pub, ok := dar.RootKeyAt(rm.CreatedAt); ok && rm.Verify(pub) == nil {
		return true
	}
	for _, pub := range darRootKeys(dar) {
		if rm.Verify(pub) == nil {
			return true
		}
	}
	return false
}

func darRootKeys(dar *identity.DomainAuthorityRecord) []ed25519.PublicKey {
	keys := make([]ed25519.PublicKey, 0, len(dar.SupersededKeys)+1)
	keys = append(keys, dar.AuthorityEd25519)
	for _, k := range dar.SupersededKeys {
		keys = append(keys, k.Ed25519Public)
	}
	return keys
}

// Close is a no-op — the registry owns no resource now (the DHT is gone; the datastore is owned and
// closed by the node). Retained so existing call sites keep compiling.
func (r *Registry) Close() error { return nil }
