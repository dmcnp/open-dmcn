package relay

import (
	"context"
	"errors"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// handlePutRecord is the fleet-replication ingest for a pushed record. It applies the one
// caller-relative check — the pusher's 'routing' fleet grant, which is anti-spam and cannot be
// evaluated inside AcceptRecord because it depends on who is asking — and then defers every
// acceptance rule to AcceptRecord.
//
// The former rationale here ("DAR/roster/removal/blocklist are self-anchoring and re-verified
// authoritatively by the reader, so a bad one is rejected there even if stored") is retired. The
// node is itself a NON-verifying reader on its hot paths, "self-anchoring" is a property of the DAR
// whose DNS anchor was never checked on this path, and an unauthenticated write is a free disk-fill
// primitive for any admitted peer regardless of how carefully readers behave.
//
// The rule that replaces it, applied uniformly by AcceptRecord: a record is stored only if the
// storing node can tell, from state it already trusts, that it is a legitimate successor of what it
// already holds.
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

	// NOTE (open-dmcn): the fleet 'routing'-grant anti-spam gate on identity pushes is a
	// fleet-ownership surface, omitted here. The record is self-authenticating (verified inside
	// AcceptRecord and re-verified by every reader), so a single self-hosted domain accepts pushes
	// for its own addresses. The key-continuity rule inside AcceptRecord is NOT a fleet surface and
	// does apply: without it, anyone who can push a record could re-bind a live address to their
	// own key.
	accepted, reason := r.AcceptRecord(ctx, req.GetKind(), req.GetRecord())
	if !accepted {
		if storageFailure(reason) {
			return errorResponse("STORAGE_FAILED", reason)
		}
		r.log.Debugf("PutRecord %s from %s rejected: %s", req.GetKind(), caller, reason)
		return reject(reason)
	}
	r.log.Debugf("PutRecord %s from %s accepted", req.GetKind(), caller)
	return accept()
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
