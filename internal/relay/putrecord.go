package relay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// handlePutRecord stores a pushed self-authenticating record into the node's RecordStore after
// re-verifying it — the fleet-replication path that replaces DHT writes. Identity pushes require
// the caller's 'routing' fleet grant (anti-spam); every kind is re-verified (so a compromised
// pusher cannot inject a forgery), and identity/DAR pushes are anti-rollback-guarded by revision.
// DAR/roster/removal/blocklist are self-anchoring (DNS/root-signed) and re-verified authoritatively
// by the reader at resolve time, so a bad one is rejected there even if stored.
func (r *Relay) handlePutRecord(caller peer.ID, req *dmcnpb.PutRecordRequest) *dmcnpb.RelayResponse {
	reject := func(reason string) *dmcnpb.RelayResponse {
		return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_PutRecord{
			PutRecord: &dmcnpb.PutRecordResponse{Reason: reason},
		}}
	}
	accept := func() *dmcnpb.RelayResponse {
		return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_PutRecord{
			PutRecord: &dmcnpb.PutRecordResponse{Accepted: true},
		}}
	}
	if r.records == nil {
		return reject("node hosts no records")
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()

	switch req.GetKind() {
	case dmcnpb.RecordKind_RECORD_KIND_IDENTITY:
		rec, err := identity.IdentityRecordFromProtoBytes(req.GetRecord())
		if err != nil {
			return reject("parse identity: " + err.Error())
		}
		if err := rec.Verify(); err != nil {
			return reject("identity self-signature invalid")
		}
		// NOTE (open-dmcn): the fleet 'routing'-grant anti-spam gate on identity pushes is a
		// fleet-ownership surface, omitted here. The record is self-authenticating (verified
		// above and re-verified by every reader), so a single self-hosted domain accepts pushes
		// for its own addresses.
		// Anti-rollback: a stale record must never overwrite a newer one.
		if existing, _ := r.records.GetIdentity(ctx, rec.Address); existing != nil {
			if rec.Revision < existing.Revision {
				return reject(fmt.Sprintf("stale revision %d < %d", rec.Revision, existing.Revision))
			}
			if rec.Revision == existing.Revision && operatorFieldIssuedAt(rec).Before(operatorFieldIssuedAt(existing)) {
				return reject("stale operator credential")
			}
		}
		if err := r.records.PutIdentity(ctx, rec); err != nil {
			return errorResponse("STORAGE_FAILED", "store identity")
		}
		r.log.Debugf("PutRecord identity %s (rev %d) from %s", rec.Address, rec.Revision, caller)
		return accept()

	case dmcnpb.RecordKind_RECORD_KIND_DAR:
		dar, err := identity.DomainAuthorityRecordFromProtoBytes(req.GetRecord())
		if err != nil {
			return reject("parse DAR: " + err.Error())
		}
		if err := dar.Verify(); err != nil {
			return reject("DAR self-signature invalid")
		}
		if existing, _ := r.records.GetDAR(ctx, dar.Domain); existing != nil && dar.Revision < existing.Revision {
			return reject(fmt.Sprintf("stale DAR revision %d < %d", dar.Revision, existing.Revision))
		}
		if err := r.records.PutDAR(ctx, dar); err != nil {
			return errorResponse("STORAGE_FAILED", "store DAR")
		}
		r.log.Debugf("PutRecord DAR %s (rev %d) from %s", dar.Domain, dar.Revision, caller)
		return accept()

	case dmcnpb.RecordKind_RECORD_KIND_ROSTER:
		roster, err := identity.FleetRosterFromProtoBytes(req.GetRecord())
		if err != nil {
			return reject("parse roster: " + err.Error())
		}
		if err := r.records.PutRoster(ctx, roster); err != nil {
			return errorResponse("STORAGE_FAILED", "store roster")
		}
		return accept()

	case dmcnpb.RecordKind_RECORD_KIND_REMOVAL:
		rm, err := identity.AddressRemovalRecordFromProtoBytes(req.GetRecord())
		if err != nil {
			return reject("parse removal: " + err.Error())
		}
		if err := r.records.PutRemoval(ctx, rm); err != nil {
			return errorResponse("STORAGE_FAILED", "store removal")
		}
		return accept()

	case dmcnpb.RecordKind_RECORD_KIND_BLOCKLIST:
		bl, err := identity.CredentialBlockListFromProtoBytes(req.GetRecord())
		if err != nil {
			return reject("parse blocklist: " + err.Error())
		}
		if err := r.records.PutBlocklist(ctx, bl); err != nil {
			return errorResponse("STORAGE_FAILED", "store blocklist")
		}
		return accept()

	default:
		return reject("unknown record kind")
	}
}

// operatorFieldIssuedAt returns the newest IssuedAt across the record's operator-owned
// credentials (routing + every OperatorCredentials entry) — zero if none. It is the
// same-revision tiebreak so an operator can re-point routing or any operator-attached
// credential without the owner advancing the revision: a re-publish is fresh iff at least
// one operator credential is newer than the stored record's.
func operatorFieldIssuedAt(rec *identity.IdentityRecord) time.Time {
	var t time.Time
	if rec.RoutingCredential != nil && rec.RoutingCredential.IssuedAt.After(t) {
		t = rec.RoutingCredential.IssuedAt
	}
	for _, c := range rec.OperatorCredentials {
		if c != nil && c.IssuedAt.After(t) {
			t = c.IssuedAt
		}
	}
	return t
}

// ClientPutRecord pushes one marshaled record of the given kind to a fleet node.
func (r *Relay) ClientPutRecord(ctx context.Context, peerID peer.ID, kind dmcnpb.RecordKind, record []byte) (bool, string, error) {
	resp, err := r.clientResolve(ctx, peerID, &dmcnpb.RelayRequest{
		Request: &dmcnpb.RelayRequest_PutRecord{PutRecord: &dmcnpb.PutRecordRequest{Kind: kind, Record: record}},
	})
	if err != nil {
		return false, "", err
	}
	pr := resp.GetPutRecord()
	if pr == nil {
		return false, "", errors.New("relay: put record: unexpected response type")
	}
	return pr.GetAccepted(), pr.GetReason(), nil
}
