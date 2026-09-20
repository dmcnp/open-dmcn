package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/dmcnpb"

	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/pairing"
)

// storageFailedPrefix marks a rejection caused by the datastore rather than by the record, so the
// caller can map it to a STORAGE_FAILED error response instead of a plain refusal.
const storageFailedPrefix = "storage: "

func storageFailure(reason string) bool { return strings.HasPrefix(reason, storageFailedPrefix) }

// ReasonRebindNeedsRemoval prefixes every rejection caused by the rebind gate. Publishers match on
// it to repair a lagging peer (push the tombstone, then retry) — PutRecordResponse carries only
// {accepted, reason} and adding a code field would be a core schema change.
const ReasonRebindNeedsRemoval = "rebind: root-signed removal required"

// ReasonRebindChainRejected prefixes every rejection of a record that asked to re-bind on its own
// rotation chain. Kept distinct from ReasonRebindNeedsRemoval because the two have different
// repairs: a missing tombstone is something the publisher can push, while a chain that does not
// verify, a domain that has not opted in, or a device too newly enrolled are all answers that
// retrying cannot change.
const ReasonRebindChainRejected = "rebind: rotation chain rejected"

// ReasonDARNotAnchored prefixes the rejection of a domain's FIRST DAR (the genesis write, which has
// no prior root to chain to) whose fingerprint is not published in _dmcn.<domain>. Publishers match
// on it to give the operator the right next step (publish the TXT, then retry).
const ReasonDARNotAnchored = "genesis DAR: fingerprint is not anchored in _dmcn DNS"

// AcceptRecord is the ONLY way a record may enter this node's RecordStore. Every write path — the
// remote PutRecord push and the node's own local write in Node.FanOutRecord — goes through it, so
// the store is closed under legitimate succession by construction rather than by every call site
// remembering to check.
//
// The invariant it enforces: a record is stored only if this node can tell, using state it already
// trusts, that the record is a legitimate successor of what it already holds.
//
// It returns (accepted, reason); reason is empty when accepted.
func (r *Relay) AcceptRecord(ctx context.Context, kind dmcnpb.RecordKind, data []byte) (bool, string) {
	if r.records == nil {
		return false, "node hosts no records"
	}
	switch kind {
	case dmcnpb.RecordKind_RECORD_KIND_IDENTITY:
		return r.acceptIdentity(ctx, data)
	case dmcnpb.RecordKind_RECORD_KIND_DAR:
		return r.acceptDAR(ctx, data)
	case dmcnpb.RecordKind_RECORD_KIND_REMOVAL:
		return r.acceptRemoval(ctx, data)
	case dmcnpb.RecordKind_RECORD_KIND_HISTORY:
		return r.acceptHistory(ctx, data)
	case dmcnpb.RecordKind_RECORD_KIND_BLOCKLIST:
		return r.acceptBlocklist(ctx, data)
	case dmcnpb.RecordKind_RECORD_KIND_ROSTER:
		return r.acceptRoster(ctx, data)
	default:
		return false, "unknown record kind"
	}
}

func (r *Relay) acceptIdentity(ctx context.Context, data []byte) (bool, string) {
	rec, err := identity.IdentityRecordFromProtoBytes(data)
	if err != nil {
		return false, "parse identity: " + err.Error()
	}
	if err := rec.Verify(); err != nil {
		return false, "identity self-signature invalid"
	}

	// Ephemeral device-pairing records live on the reserved, non-routable pairing.local domain.
	// They have no DAR, confer no power, expire in ~15 minutes, and can only overwrite another
	// ephemeral, so the domain gates below do not apply. Anti-rollback still does.
	if !pairing.IsEphemeralAddress(rec.Address) {
		dar, _ := r.records.GetDAR(ctx, domainverify.DomainOf(rec.Address))
		if reason, ok := r.checkReservedLocalPart(ctx, rec, dar); !ok {
			return false, reason
		}
		if reason, ok := r.checkKeyContinuity(ctx, rec, dar); !ok {
			return false, reason
		}
	}

	if existing, _ := r.records.GetIdentity(ctx, rec.Address); existing != nil {
		if rec.Revision < existing.Revision {
			return false, fmt.Sprintf("stale revision %d < %d", rec.Revision, existing.Revision)
		}
		if rec.Revision == existing.Revision && operatorFieldIssuedAt(rec).Before(operatorFieldIssuedAt(existing)) {
			return false, "stale operator credential"
		}
	}
	if err := r.records.PutIdentity(ctx, rec); err != nil {
		return false, storageFailedPrefix + "store identity"
	}
	return true, ""
}

// checkKeyContinuity is the rebind gate: a record may only displace one bound to a DIFFERENT owner
// key when the domain root has tombstoned the incumbent. This is what makes the AddressRemovalRecord
// contract real — "only root can free an address for re-binding" — because an AddressCredential is
// an ordinary role-bearing leaf that any `address`-granted issuer may mint for any key.
//
// A self-hosted daemon may legitimately hold no DAR for a domain it serves. Failing closed there
// would leave the operator with no recovery path at all, so this warns and allows; a node that does
// hold the DAR gets the full check.
func (r *Relay) checkKeyContinuity(ctx context.Context, rec *identity.IdentityRecord, dar *identity.DomainAuthorityRecord) (string, bool) {
	prev, _ := r.records.GetIdentity(ctx, rec.Address)
	if prev == nil {
		return "", true // genesis — nothing to displace
	}
	var rm *identity.AddressRemovalRecord
	if dar != nil {
		rm = r.storedRemoval(ctx, dar, rec.Address)
	}
	arm, err := identity.AuthorizeRebind(prev, rec, rm, dar, time.Now())
	switch {
	case err == nil:
		switch arm {
		case identity.RebindRootTombstone:
			r.log.Infof("address %s re-bound to a new key under a root-signed tombstone", rec.Address)
		case identity.RebindOwnerRotation:
			// Counted only on the arm that actually re-keys, so a republish of the SAME record
			// takes the same-key arm and spends nothing.
			if r.rotationLimiter != nil && !r.rotationLimiter.Allow(strings.ToLower(rec.Address)) {
				return fmt.Sprintf("%s has been re-keyed too many times today — try again later", rec.Address), false
			}
			r.log.Infof("address %s re-keyed by its owner (revision %d, %d transitions on record)",
				rec.Address, rec.Revision, len(rec.RotationChain))
		}
		return "", true
	case errors.Is(err, identity.ErrRebindUnverifiable):
		r.log.Warnf("accepting a key change for %s without a domain authority record", rec.Address)
		return "", true
	default:
		// Route the rejection by what the record was ASKING for. A publisher repairs a
		// ReasonRebindNeedsRemoval by pushing the tombstone this peer is missing and retrying;
		// a record that came in on its own rotation chain has no such repair.
		if len(rec.RotationChain) > 0 {
			return ReasonRebindChainRejected + ": " + err.Error(), false
		}
		return ReasonRebindNeedsRemoval + ": " + err.Error(), false
	}
}

// checkReservedLocalPart gates role addresses (postmaster@, abuse@ …) a domain reserves in its DAR.
// These are never self-serve issuable, so a record claiming one must carry a valid address
// credential from a DAR-enrolled issuer.
func (r *Relay) checkReservedLocalPart(ctx context.Context, rec *identity.IdentityRecord, dar *identity.DomainAuthorityRecord) (string, bool) {
	if dar == nil || !dar.ReservesLocalPart(domainverify.LocalPartOf(rec.Address)) {
		return "", true
	}
	if !rec.HasAddressCredential() {
		return fmt.Sprintf("%s is a reserved local-part on %s and requires a domain address credential", rec.Address, dar.Domain), false
	}
	cred := rec.AddressCredential
	if cred.Address != rec.Address || !cred.HasRole(identity.RoleAddress) || !bytes.Equal(cred.Subject, rec.Ed25519Public) {
		return "address credential does not match the record", false
	}
	var blocks *identity.CredentialBlockList
	if b, err := r.records.GetBlocklistBytes(ctx, dar.Domain); err == nil && len(b) > 0 {
		if bl, perr := identity.CredentialBlockListFromProtoBytes(b); perr == nil && identity.BlocklistIsRootSigned(dar, bl) {
			blocks = bl
		}
	}
	if err := identity.VerifyCredential(cred, dar, blocks, time.Now()); err != nil {
		return "address credential for a reserved local-part does not verify: " + err.Error(), false
	}
	return "", true
}

// acceptDAR admits a DAR by root-key continuity, or — for a domain this node holds no DAR for — by
// the _dmcn DNS anchor. dar.Verify() only proves the record was signed by the key it carries (it is
// self-anchoring), so without those checks any admitted peer could install a DAR naming its own
// root key, and every downstream check that trusts the local DAR (RemovalIsRootSigned, and
// therefore the rebind gate itself) would inherit the forgery.
func (r *Relay) acceptDAR(ctx context.Context, data []byte) (bool, string) {
	dar, err := identity.DomainAuthorityRecordFromProtoBytes(data)
	if err != nil {
		return false, "parse DAR: " + err.Error()
	}
	if err := dar.Verify(); err != nil {
		return false, "DAR self-signature invalid"
	}
	existing, _ := r.records.GetDAR(ctx, dar.Domain)
	if existing != nil {
		if !darAcknowledges(dar, existing.AuthorityEd25519) {
			return false, fmt.Sprintf("DAR for %s does not acknowledge the currently trusted root key (rotation must supersede it)", dar.Domain)
		}
		if dar.Revision < existing.Revision {
			return false, fmt.Sprintf("stale DAR revision %d < %d", dar.Revision, existing.Revision)
		}
		// At an EQUAL revision, accept only a byte-identical record: plain >= let a forgery
		// overwrite, while plain > would break idempotent re-publishing.
		if dar.Revision == existing.Revision {
			if prior, err := r.records.GetDARBytes(ctx, dar.Domain); err == nil && !bytes.Equal(prior, data) {
				return false, fmt.Sprintf("conflicting DAR for %s at revision %d (a change must advance the revision)", dar.Domain, dar.Revision)
			}
		}
	} else if r.darAnchor != nil {
		// Genesis DAR: no prior root to chain to, so the write-time gate is the _dmcn fingerprint
		// anchor. Fail-closed on purpose: the self-host flow publishes the TXT before the DAR, so
		// a rejection here means the record arrived early or from someone who is not the domain's
		// operator, and a lookup failure must not let an unanchored root become the key every
		// later check trusts.
		if err := r.darAnchor(ctx, dar.Domain, dar.Fingerprint()); err != nil {
			return false, fmt.Sprintf("%s: publish the _dmcn TXT for %s first: %v", ReasonDARNotAnchored, dar.Domain, err)
		}
	}
	if err := r.records.PutDAR(ctx, dar); err != nil {
		return false, storageFailedPrefix + "store DAR"
	}
	return true, ""
}

// darAcknowledges reports whether dar's root timeline vouches for key.
func darAcknowledges(dar *identity.DomainAuthorityRecord, key []byte) bool {
	if bytes.Equal(dar.AuthorityEd25519, key) {
		return true
	}
	for _, k := range dar.SupersededKeys {
		if bytes.Equal(k.Ed25519Public, key) {
			return true
		}
	}
	return false
}

// acceptRemoval authenticates a removal tombstone: it is signed either by a domain root key under
// a DAR this node already holds, or by the address's OWN key (the holder retiring itself), and the
// binding set may only GROW. Revision alone would let a partitioned fleet silently lose tombstones;
// the superset rule alone would let a stale-but-larger record win. Both together make it a monotone
// set with a total order.
//
// PRECEDENCE: a root-signed record may displace an owner-signed one — that is the operator
// override, and it is how an address self-retired by its holder can still be rotated or reissued
// by the domain. An owner-signed record may NEVER displace a root-signed one, or a stolen key
// could overwrite the operator's tombstone, shut the rebind gate and block the very recovery the
// root-only rule exists to preserve.
func (r *Relay) acceptRemoval(ctx context.Context, data []byte) (bool, string) {
	rm, err := identity.AddressRemovalRecordFromProtoBytes(data)
	if err != nil {
		return false, "parse removal: " + err.Error()
	}
	if rm.Address == "" || rm.Domain == "" {
		return false, "removal record missing domain or address"
	}
	if !strings.EqualFold(rm.Domain, domainverify.DomainOf(rm.Address)) {
		return false, fmt.Sprintf("removal record domain %q does not match address %q", rm.Domain, rm.Address)
	}
	dar, _ := r.records.GetDAR(ctx, rm.Domain)
	if dar == nil {
		return false, fmt.Sprintf("no domain authority held for %s — cannot verify the removal record", rm.Domain)
	}
	// Who signed it. Owner-signed needs the address's own record to check against, so a node that
	// does not hold it cannot verify one — the same posture as a missing DAR, and for the same
	// reason: "cannot verify" must never read as "verified".
	rootSigned := identity.RemovalIsRootSigned(dar, rm)
	ownerSigned := false
	if !rootSigned {
		if rec, gerr := r.records.GetIdentity(ctx, rm.Address); gerr == nil && rec != nil {
			ownerSigned = identity.RemovalIsOwnerSigned(rec, rm)
		}
	}
	if !rootSigned && !ownerSigned {
		return false, fmt.Sprintf("removal record for %s is signed by neither a domain root key nor the address's own key", rm.Address)
	}
	if existing := r.storedRemovalAny(ctx, rm.Address); existing != nil {
		if !rootSigned && identity.RemovalIsRootSigned(dar, existing) {
			return false, fmt.Sprintf("removal record for %s is owner-signed and would displace a root-signed one", rm.Address)
		}
		if rm.Revision < existing.Revision {
			return false, fmt.Sprintf("stale removal revision %d < %d", rm.Revision, existing.Revision)
		}
		if missing, ok := removalCovers(rm, existing); !ok {
			return false, fmt.Sprintf("removal record drops %d previously tombstoned binding(s) — append-only", missing)
		}
	}
	if err := r.records.PutRemoval(ctx, rm); err != nil {
		return false, storageFailedPrefix + "store removal"
	}
	return true, ""
}

// storedRemovalAny returns this node's current removal record for address whatever signed it.
// The append-only and precedence rules in acceptRemoval must see every stored record, including an
// owner-signed one; only the rebind gate narrows to root-signed, which is what storedRemoval is for.
func (r *Relay) storedRemovalAny(ctx context.Context, address string) *identity.AddressRemovalRecord {
	b, err := r.records.GetRemovalBytes(ctx, address)
	if err != nil || len(b) == 0 {
		return nil
	}
	rm, err := identity.AddressRemovalRecordFromProtoBytes(b)
	if err != nil {
		return nil
	}
	return rm
}

// storedRemoval returns this node's current removal record for address, but only if it still
// verifies as root-signed under dar.
func (r *Relay) storedRemoval(ctx context.Context, dar *identity.DomainAuthorityRecord, address string) *identity.AddressRemovalRecord {
	b, err := r.records.GetRemovalBytes(ctx, address)
	if err != nil || len(b) == 0 {
		return nil
	}
	rm, err := identity.AddressRemovalRecordFromProtoBytes(b)
	if err != nil || !identity.RemovalIsRootSigned(dar, rm) {
		return nil
	}
	return rm
}

// removalCovers reports whether next tombstones every binding prior does, returning the count it
// drops when it does not.
func removalCovers(next, prior *identity.AddressRemovalRecord) (int, bool) {
	missing := 0
	for _, b := range prior.RemovedBindings {
		if _, ok := next.Removed(b.Ed25519Public); !ok {
			missing++
		}
	}
	return missing, missing == 0
}

// acceptBlocklist requires the root signature the reader already demands, so a forged blocklist
// cannot be parked in the store to revoke a legitimate issuer's credentials.
func (r *Relay) acceptBlocklist(ctx context.Context, data []byte) (bool, string) {
	bl, err := identity.CredentialBlockListFromProtoBytes(data)
	if err != nil {
		return false, "parse blocklist: " + err.Error()
	}
	dar, _ := r.records.GetDAR(ctx, bl.Domain)
	if dar == nil {
		return false, fmt.Sprintf("no domain authority held for %s — cannot verify the blocklist", bl.Domain)
	}
	if !identity.BlocklistIsRootSigned(dar, bl) {
		return false, fmt.Sprintf("blocklist for %s is not signed by a domain root key", bl.Domain)
	}
	if b, err := r.records.GetBlocklistBytes(ctx, bl.Domain); err == nil && len(b) > 0 {
		if existing, perr := identity.CredentialBlockListFromProtoBytes(b); perr == nil &&
			identity.BlocklistIsRootSigned(dar, existing) && bl.Revision < existing.Revision {
			return false, fmt.Sprintf("stale blocklist revision %d < %d", bl.Revision, existing.Revision)
		}
	}
	if err := r.records.PutBlocklist(ctx, bl); err != nil {
		return false, storageFailedPrefix + "store blocklist"
	}
	return true, ""
}

func (r *Relay) acceptRoster(ctx context.Context, data []byte) (bool, string) {
	roster, err := identity.FleetRosterFromProtoBytes(data)
	if err != nil {
		return false, "parse roster: " + err.Error()
	}
	if err := r.records.PutRoster(ctx, roster); err != nil {
		return false, storageFailedPrefix + "store roster"
	}
	return true, ""
}

// acceptHistory admits an address's complete rotation history.
//
// The record carries no signature of its own and needs none: every entry is signed by the key it
// retires and by the key taking over, so extending the history takes keys the extender must
// genuinely hold. Admission is therefore the chain walk plus two rules about how it may change.
//
// Deliberately no grant gate, for the same reason acceptRemoval has none: the entries' signatures
// are stronger admission control than any fleet grant. What bounds STORAGE is different, and the
// "idempotently keyed by address" argument only ever covered half of it: one address cannot grow
// without limit, but nothing stopped a pusher inventing addresses. Requiring an identity record
// this node already holds is what closes that — and, because it is checked before the chain walk,
// it bounds the verification work a rejected record can cost as well.
func (r *Relay) acceptHistory(ctx context.Context, data []byte) (bool, string) {
	var pb dmcnpb.AddressHistoryRecord
	if err := proto.Unmarshal(data, &pb); err != nil {
		return false, "malformed history record"
	}
	rec, err := identity.AddressHistoryRecordFromProto(&pb)
	if err != nil {
		return false, "malformed history record: " + err.Error()
	}
	if rec.Address == "" || rec.Domain == "" {
		return false, "history record names no address"
	}
	// This daemon serves the domains it holds authority records for, which is the same test
	// acceptRemoval applies. (The product fork asks its fleet-permit set instead — a posture this
	// single-operator core has no concept of.)
	if dar, _ := r.records.GetDAR(ctx, rec.Domain); dar == nil {
		return false, "no domain authority held for " + rec.Domain + " — this node does not serve it"
	}

	// The address has to be one this node already knows, and that is checked FIRST — before the
	// chain walk, which is the expensive part. A history is an explanation of how a record came to
	// hold the keys it holds; without the record there is nothing being explained, and a pusher
	// could otherwise hand out verification work and storage for addresses it invented.
	live, _ := r.records.GetIdentity(ctx, rec.Address)
	if live == nil {
		return false, "no identity record for " + rec.Address + " — publish the record before its history"
	}
	if err := rec.Verify(); err != nil {
		return false, "history record does not verify: " + err.Error()
	}

	// APPEND-ONLY. A history may only grow, so nothing already written can be quietly rewritten
	// by a later publish — which is the whole of what makes this record worth reading. An equal
	// chain is not an extension, so a re-publish of unchanged history is accepted as a no-op
	// rather than rejected: fan-out repeats, and a peer catching up must not look like an attack.
	prior, _ := r.records.GetHistory(ctx, rec.Address)
	if prior != nil && len(prior.Chain) > 0 {
		if chainsEqual(prior.Chain, rec.Chain) {
			return true, ""
		}
		if !rec.Extends(prior) {
			return false, "history record does not extend the one already held (histories only grow)"
		}
	}

	// And it must describe the address as this node knows it. A history whose last transition
	// hands over to some other key is either stale or about a different account, and storing it
	// would leave this node serving a past that contradicts its own present.
	if last := rec.Terminal(); last != nil && !bytes.Equal(last.NextEd25519Public, live.Ed25519Public) {
		return false, "history record disagrees with the identity record this node holds"
	}

	if err := r.records.PutHistory(ctx, rec); err != nil {
		r.log.Errorf("store history for %s: %v", rec.Address, err)
		return false, "failed to store the history record"
	}
	r.log.Infof("stored rotation history for %s (%d transitions)", rec.Address, len(rec.Chain))
	return true, ""
}

// chainsEqual reports whether two chains are the same, compared on each entry's signature —
// which covers every field, so agreement there is agreement throughout.
func chainsEqual(a, b []identity.RotationEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Signature, b[i].Signature) {
			return false
		}
	}
	return true
}
