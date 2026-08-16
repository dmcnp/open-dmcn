package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/pairing"
	"dmcn.dev/open-dmcn/internal/registry"
)

// ErrNotFound is returned when an address has no record on its authoritative fleet. It aliases
// registry.ErrNotFound so existing callers that check errors.Is(err, registry.ErrNotFound) keep
// working during the DHT migration.
var ErrNotFound = registry.ErrNotFound

// resolveDNS resolves a domain's _dmcn TXT record set. A package var so tests can inject fake DNS
// (mirroring the domainverify.lookupTXT / protoMarshal override pattern used elsewhere).
var resolveDNS = domainverify.Resolve

// lowerDNSMap lowercases the keys of a static _dmcn map (nil for empty input).
func lowerDNSMap(m map[string]domainverify.Record) map[string]domainverify.Record {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]domainverify.Record, len(m))
	for k, v := range m {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

// resolveDomain resolves a domain's _dmcn record, consulting the static config first (dev/CI +
// operator seed-pin) and falling back to real DNS. Returns a COPY so callers can't mutate the map.
func (n *Node) resolveDomain(ctx context.Context, domain string) (*domainverify.Record, error) {
	if n.staticDNS != nil {
		if rec, ok := n.staticDNS[strings.ToLower(domain)]; ok {
			cp := rec
			cp.Seeds = append([]string(nil), rec.Seeds...)
			return &cp, nil
		}
	}
	return resolveDNS(ctx, domain)
}

// Resolve looks up an address's IdentityRecord authoritatively via DNS discovery + the domain's
// fleet-served signed records, verifying entirely against the domain's DNS fingerprint — with NO
// DHT. It is the drop-in replacement for registry.Lookup:
//
//  1. Resolve the mailbox domain's _dmcn TXT → fingerprint (trust anchor) + optional fleet= deferral.
//  2. Follow the deferral to the fleet domain's _dmcn TXT → seed endpoints (bootstrap, round-robin).
//  3. Dial a seed over libp2p, fetch the mailbox DAR + the IdentityRecord, and verify both against
//     the mailbox fingerprint (self-sig, DNS anchor, signed fleet_domain == DNS fleet=, credential
//     chain). A wrong/hostile fleet is DoS-only — it cannot produce fingerprint-anchored records.
//
// Seeds are tried in order (failover); a definitive not-found from a DAR-verified fleet node is
// authoritative and returned immediately.
func (n *Node) Resolve(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	domain := domainverify.DomainOf(address)
	if domain == "" {
		return nil, fmt.Errorf("node: resolve: invalid address %q", address)
	}

	// Throwaway device-pairing records live on the synthetic pairing.local domain, which has no
	// _dmcn TXT and no DAR — so the DNS/DAR-anchored path below can't reach them. They are fanned
	// out to fleet RecordStores at pair-register time and are self-certifying, so resolve them by
	// pulling straight from a connected fleet peer (self-signature is the only trust). This is the
	// fleet-era replacement for the DHT's keyed global lookup the pairing flow used to rely on.
	if pairing.IsEphemeralAddress(address) {
		return n.resolveEphemeral(ctx, address)
	}

	// 1-2. DNS: mailbox fingerprint (trust anchor) + follow fleet deferral → bootstrap seeds.
	mrec, seeds, err := n.dnsDiscover(ctx, domain)
	if err != nil {
		return nil, err
	}

	// 3. Dial seeds (failover) and fetch + verify.
	var lastErr error
	for _, seed := range seeds {
		rec, verr := n.resolveVia(ctx, seed, address, domain, mrec)
		if verr == nil {
			return rec, nil
		}
		if errors.Is(verr, ErrNotFound) {
			return nil, verr // authoritative: a DAR-verified fleet node has no such record
		}
		lastErr = verr // transport/verify failure on this seed — try the next
	}
	return nil, fmt.Errorf("node: resolve %s: all %d seed(s) failed: %w", address, len(seeds), lastErr)
}

// resolveVia fetches + verifies an address's record through a single seed endpoint. It returns
// ErrNotFound when the (DAR-verified) fleet node reports the record absent.
func (n *Node) resolveVia(ctx context.Context, seed, address, domain string, mrec *domainverify.Record) (*identity.IdentityRecord, error) {
	info, err := ParseRelayHint(seed)
	if err != nil {
		return nil, fmt.Errorf("seed %q: %w", seed, err)
	}
	if info.ID != n.host.ID() {
		if err := n.host.Connect(ctx, *info); err != nil {
			return nil, fmt.Errorf("connect seed %s: %w", info.ID, err)
		}
	}

	// Fetch + verify the mailbox domain's DAR.
	darBytes, err := n.relay.ClientGetDAR(ctx, info.ID, domain)
	if err != nil {
		return nil, fmt.Errorf("fetch DAR: %w", err)
	}
	if darBytes == nil {
		return nil, fmt.Errorf("fleet serves no DAR for %s", domain)
	}
	dar, err := identity.DomainAuthorityRecordFromProtoBytes(darBytes)
	if err != nil {
		return nil, fmt.Errorf("parse DAR: %w", err)
	}
	if err := verifyDAR(dar, mrec); err != nil {
		return nil, err
	}

	// Fetch the identity record.
	recBytes, err := n.relay.ClientGetIdentity(ctx, info.ID, address)
	if err != nil {
		return nil, fmt.Errorf("fetch identity: %w", err)
	}
	if recBytes == nil {
		return nil, ErrNotFound
	}
	rec, err := identity.IdentityRecordFromProtoBytes(recBytes)
	if err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}

	// Companion records for full verification (best-effort; absence ⇒ fail-open like the DHT path).
	// Only honor a blocklist actually signed by the domain root — otherwise a hostile fleet could
	// censor a valid credential with a forged blocklist. Same for the removal tombstone, which
	// VerifyManagedRecord gates on RemovalIsRootSigned.
	var blocks *identity.CredentialBlockList
	if blBytes, _ := n.relay.ClientGetBlocklist(ctx, info.ID, domain); blBytes != nil {
		if bl, berr := identity.CredentialBlockListFromProtoBytes(blBytes); berr == nil && identity.BlocklistIsRootSigned(dar, bl) {
			blocks = bl
		}
	}
	var removal *identity.AddressRemovalRecord
	if rmBytes, _ := n.relay.ClientGetRemoval(ctx, info.ID, address); rmBytes != nil {
		removal, _ = identity.AddressRemovalRecordFromProtoBytes(rmBytes)
	}

	// Verify the record against the DAR — pure, DHT-free.
	if _, err := identity.VerifyManagedRecord(rec, dar, blocks, removal, time.Now()); err != nil {
		return nil, fmt.Errorf("record verification: %w", err)
	}
	return rec, nil
}

// resolveEphemeral resolves a throwaway device-pairing record (reserved pairing.local domain)
// WITHOUT DNS/DAR discovery. pairing.local is synthetic — no _dmcn TXT, no DAR — so the normal
// resolver can't reach it; instead the record is published to fleet RecordStores at pair-register
// time (grant-exempt for this domain) and pulled straight from a connected fleet peer here. The
// record is self-certifying, so only its self-signature is checked — a wrong/hostile peer is
// DoS-only, never a forgery vector, exactly like the DAR path. Returns ErrNotFound when no reachable
// peer holds it.
func (n *Node) resolveEphemeral(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	// A serving node that accepted the push has it locally.
	if n.records != nil {
		if data, _ := n.records.GetIdentityBytes(ctx, address); data != nil {
			if rec, err := identity.IdentityRecordFromProtoBytes(data); err == nil && rec.Verify() == nil {
				return rec, nil
			}
		}
	}
	var lastErr error
	tried := map[peer.ID]bool{}
	try := func(pid peer.ID) *identity.IdentityRecord {
		if pid == n.host.ID() || tried[pid] {
			return nil
		}
		tried[pid] = true
		data, err := n.relay.ClientGetIdentity(ctx, pid, address)
		if err != nil {
			lastErr = err
			return nil
		}
		if data == nil {
			return nil // this peer simply doesn't hold it — keep looking
		}
		rec, perr := identity.IdentityRecordFromProtoBytes(data)
		if perr != nil {
			lastErr = perr
			return nil
		}
		if verr := rec.Verify(); verr != nil {
			lastErr = verr
			return nil
		}
		return rec
	}
	// Already-connected peers first (no dial), then configured seeds (dial as needed).
	for _, pid := range n.host.Network().Peers() {
		if rec := try(pid); rec != nil {
			return rec, nil
		}
	}
	for _, p := range n.peers {
		info, perr := ParseRelayHint(p)
		if perr != nil {
			continue
		}
		if info.ID != n.host.ID() {
			if cerr := n.host.Connect(ctx, *info); cerr != nil {
				lastErr = cerr
				continue
			}
		}
		if rec := try(info.ID); rec != nil {
			return rec, nil
		}
	}
	if lastErr != nil {
		return nil, fmt.Errorf("node: resolve ephemeral %s: %w", address, lastErr)
	}
	return nil, ErrNotFound
}

// verifyDAR checks a fetched DAR against the mailbox domain's DNS anchor (pure). The DNS `fp=`
// fingerprint is the trust boundary: the DAR — and every record chaining to it — must verify
// against it, so a wrong/hostile fleet is DoS-only, never a forgery vector. The `fleet=` pointer is
// discovery, not trust; a spoofed one is DoS-only.
//
// Fleet-deferral pinning is OPT-IN: the DNS `fleet=` must match the DAR's signed `fleet_domain`
// only when the DAR actually declares one. This is situational defense-in-depth — it matters only
// for a client that pins `fp=` but re-resolves `fleet=`/`seed=` (catching a fleet= redirect under a
// current-DNS tamper); in plain DNS, whoever can move `fleet=` can also move `fp=` and forge the
// chain, so mandating it buys little. A DAR that declares no `fleet_domain` follows the DNS `fleet=`
// as pure discovery, so deferral works without any DAR-side wiring (set it via `domain register
// --fleet` to opt into the pinning).
func verifyDAR(dar *identity.DomainAuthorityRecord, mrec *domainverify.Record) error {
	if err := dar.Verify(); err != nil {
		return fmt.Errorf("DAR self-signature: %w", err)
	}
	if !strings.EqualFold(dar.Fingerprint(), mrec.Fingerprint) {
		return fmt.Errorf("DAR fingerprint %s != DNS anchor %s", dar.Fingerprint(), mrec.Fingerprint)
	}
	if signedFleet, ok := dar.DefersToFleet(); ok && mrec.Fleet != signedFleet {
		return fmt.Errorf("fleet deferral mismatch: DNS fleet=%q, signed DAR fleet_domain=%q", mrec.Fleet, signedFleet)
	}
	return nil
}

// domainNotDiscoverable reports whether a discovery error means the domain simply publishes no
// _dmcn authority — an NXDOMAIN or a missing/empty _dmcn record. That is an authoritative "not a
// managed / not-yet-registered domain", which callers map to registry.ErrNotFound (open
// registration, or a genesis DAR for `domain register`) — distinct from a transient DNS/fleet
// failure, which must stay a hard error (fail-closed for policy lookups).
func domainNotDiscoverable(err error) bool {
	if errors.Is(err, domainverify.ErrNoRecord) {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// dnsDiscover resolves a domain's _dmcn record and follows one level of fleet deferral to the
// bootstrap seed endpoints. Returns the mailbox record (trust anchor) + the seeds to dial. A domain
// that publishes no _dmcn authority (NXDOMAIN / no record / no fingerprint) yields registry.ErrNotFound
// so callers can treat it as unregistered; a transient failure or a broken fleet deferral stays a hard error.
func (n *Node) dnsDiscover(ctx context.Context, domain string) (*domainverify.Record, []string, error) {
	mrec, err := n.resolveDomain(ctx, domain)
	if err != nil {
		if domainNotDiscoverable(err) {
			return nil, nil, fmt.Errorf("node: resolve: %s not registered: %w", domain, registry.ErrNotFound)
		}
		return nil, nil, fmt.Errorf("node: resolve: mailbox dns %s: %w", domain, err)
	}
	if mrec.Fingerprint == "" {
		return nil, nil, fmt.Errorf("node: resolve: %s has no _dmcn fingerprint: %w", domain, registry.ErrNotFound)
	}
	fleetDomain, seeds := domain, mrec.Seeds
	if mrec.Fleet != "" {
		fleetDomain = mrec.Fleet
		frec, ferr := n.resolveDomain(ctx, fleetDomain)
		if ferr != nil {
			return nil, nil, fmt.Errorf("node: resolve: fleet dns %s: %w", fleetDomain, ferr)
		}
		seeds = frec.Seeds
	}
	if len(seeds) == 0 {
		return nil, nil, fmt.Errorf("node: resolve: no seed endpoints for fleet %s", fleetDomain)
	}
	return mrec, seeds, nil
}

// ResolveDAR resolves + verifies a domain's DomainAuthorityRecord authoritatively via its fleet
// (DNS discovery → dial seed → fetch → anchor), with NO DHT. The DHT-free replacement for
// registry.LookupDomainAuthority.
func (n *Node) ResolveDAR(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error) {
	mrec, seeds, err := n.dnsDiscover(ctx, domain)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, seed := range seeds {
		info, perr := ParseRelayHint(seed)
		if perr != nil {
			lastErr = perr
			continue
		}
		if info.ID != n.host.ID() {
			if cerr := n.host.Connect(ctx, *info); cerr != nil {
				lastErr = cerr
				continue
			}
		}
		darBytes, gerr := n.relay.ClientGetDAR(ctx, info.ID, domain)
		if gerr != nil {
			lastErr = gerr
			continue
		}
		if darBytes == nil {
			return nil, ErrNotFound
		}
		dar, derr := identity.DomainAuthorityRecordFromProtoBytes(darBytes)
		if derr != nil {
			lastErr = derr
			continue
		}
		if verr := verifyDAR(dar, mrec); verr != nil {
			lastErr = verr
			continue
		}
		return dar, nil
	}
	return nil, fmt.Errorf("node: resolve DAR %s: all seed(s) failed: %w", domain, lastErr)
}

// Lookup resolves an address's IdentityRecord, RecordStore-first (a serving node's own authoritative
// records) then the DNS-seeded fleet resolver — the unified, DHT-free read entry point for the
// services. Returns ErrNotFound when the address's fleet has no record for it.
func (n *Node) Lookup(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	return n.registry.Lookup(ctx, address)
}

// LookupDAR resolves a domain's DAR RecordStore-first then via the fleet resolver (see Lookup).
func (n *Node) LookupDAR(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error) {
	return n.registry.LookupDomainAuthority(ctx, domain)
}

// ResolveRelayDescriptor fetches a relay's onion descriptor from the relay's own node via the fleet
// op (the descriptor is self-anchored — signed by the node's libp2p key, recoverable from the peer
// ID — so it is verified without trusting the server). No DHT. Returns ErrNotFound when absent.
func (n *Node) ResolveRelayDescriptor(ctx context.Context, peerID string) (*identity.RelayDescriptor, error) {
	return n.registry.LookupRelayDescriptor(ctx, peerID)
}

// resolveDescriptorViaFleet fetches a relay descriptor from the local RecordStore (own peer) or the
// peer's own node, verifying it self-anchored from the peer ID. PURE (no DHT / registry fallback),
// so it is safe to use as the registry's DHT-free descriptor source. Returns (nil, nil) when absent.
func (n *Node) resolveDescriptorViaFleet(ctx context.Context, peerID string) (*identity.RelayDescriptor, error) {
	pid, err := peer.Decode(peerID)
	if err != nil {
		return nil, nil
	}
	if pid == n.host.ID() {
		if n.records != nil {
			if data, _ := n.records.GetRelayDescriptorBytes(ctx, peerID); data != nil {
				return identity.RelayDescriptorFromProtoBytes(data)
			}
		}
		return nil, nil
	}
	data, ferr := n.relay.ClientGetRelayDescriptor(ctx, pid, peerID)
	if ferr != nil || data == nil {
		return nil, ferr
	}
	desc, derr := identity.RelayDescriptorFromProtoBytes(data)
	if derr != nil || !relayDescriptorSelfValid(desc) {
		return nil, derr
	}
	return desc, nil
}

// fleetBytes dials the domain's fleet seeds (failover) and runs fetch against the first reachable,
// returning the raw record bytes (nil ⇒ the fleet reports the record absent). PURE (no DHT).
func (n *Node) fleetBytes(ctx context.Context, domain string, fetch func(context.Context, peer.ID) ([]byte, error)) ([]byte, error) {
	_, seeds, err := n.dnsDiscover(ctx, domain)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, seed := range seeds {
		info, perr := ParseRelayHint(seed)
		if perr != nil {
			lastErr = perr
			continue
		}
		if info.ID != n.host.ID() {
			if cerr := n.host.Connect(ctx, *info); cerr != nil {
				lastErr = cerr
				continue
			}
		}
		data, ferr := fetch(ctx, info.ID)
		if ferr != nil {
			lastErr = ferr
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("node: fleet fetch for %s: %w", domain, lastErr)
}

// darForSource returns a domain's DAR local-first then via the fleet resolver. PURE.
func (n *Node) darForSource(ctx context.Context, domain string) (*identity.DomainAuthorityRecord, error) {
	if n.records != nil {
		if dar, _ := n.records.GetDAR(ctx, domain); dar != nil {
			return dar, nil
		}
	}
	return n.ResolveDAR(ctx, domain)
}

// resolveRemovalViaFleet fetches an address's removal tombstone local-first then via the fleet. The
// caller (VerifyManagedRecord) verifies its root signature. PURE. (nil, nil) when absent.
func (n *Node) resolveRemovalViaFleet(ctx context.Context, address string) (*identity.AddressRemovalRecord, error) {
	if n.records != nil {
		if data, _ := n.records.GetRemovalBytes(ctx, address); data != nil {
			return identity.AddressRemovalRecordFromProtoBytes(data)
		}
	}
	data, err := n.fleetBytes(ctx, domainverify.DomainOf(address), func(ctx context.Context, pid peer.ID) ([]byte, error) {
		return n.relay.ClientGetRemoval(ctx, pid, address)
	})
	if err != nil || data == nil {
		return nil, err
	}
	return identity.AddressRemovalRecordFromProtoBytes(data)
}

// resolveBlocklistViaFleet fetches a domain's blocklist local-first then via the fleet, returning it
// ONLY if root-signed (else nil — a hostile fleet cannot censor via a forged blocklist). PURE.
func (n *Node) resolveBlocklistViaFleet(ctx context.Context, domain string) (*identity.CredentialBlockList, error) {
	var raw []byte
	if n.records != nil {
		raw, _ = n.records.GetBlocklistBytes(ctx, domain)
	}
	if raw == nil {
		data, err := n.fleetBytes(ctx, domain, func(ctx context.Context, pid peer.ID) ([]byte, error) {
			return n.relay.ClientGetBlocklist(ctx, pid, domain)
		})
		if err != nil || data == nil {
			return nil, err
		}
		raw = data
	}
	bl, err := identity.CredentialBlockListFromProtoBytes(raw)
	if err != nil {
		return nil, err
	}
	dar, derr := n.darForSource(ctx, domain)
	if derr != nil || dar == nil || !identity.BlocklistIsRootSigned(dar, bl) {
		return nil, nil
	}
	return bl, nil
}

// recordSource builds the registry's DHT-free record source: every closure reads local-first
// (RecordStore) then the fleet resolver, and NONE calls back into registry.Lookup* (no recursion).
func (n *Node) recordSource() *registry.RecordSource {
	return &registry.RecordSource{
		Identity: func(ctx context.Context, address string) (*identity.IdentityRecord, error) {
			if n.records != nil {
				if rec, _ := n.records.GetIdentity(ctx, address); rec != nil {
					return rec, nil
				}
			}
			return n.Resolve(ctx, address)
		},
		DAR:        n.darForSource,
		Removal:    n.resolveRemovalViaFleet,
		Blocklist:  n.resolveBlocklistViaFleet,
		Descriptor: n.resolveDescriptorViaFleet,
	}
}

// relayDescriptorSelfValid verifies a descriptor's signature against the key recovered from its
// peer ID (self-anchored), so a fleet-served descriptor is trusted no more than the DHT one was.
func relayDescriptorSelfValid(desc *identity.RelayDescriptor) bool {
	pid, err := peer.Decode(desc.PeerID)
	if err != nil {
		return false
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil || pub == nil {
		return false
	}
	signable, err := desc.SignableBytes()
	if err != nil {
		return false
	}
	ok, verr := pub.Verify(signable, desc.Signature)
	return verr == nil && ok
}
