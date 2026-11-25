package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/relay"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// This backend shares the daemon's node in-process rather than dialing a remote
// relay, so RelayProxy is transport-neutral: the challenge/complete two-phase
// (which preserves zero-knowledge — the browser signs each nonce) is expressed as
// (address, nonce, signature) rather than a held-open libp2p stream. The relay
// generates the nonce; the address the caller proved a session for identifies the
// mailbox; the signature over the nonce is verified against the address's record.

var (
	// ErrMailboxFull is the send-path counterpart: a STORE the recipient's mailbox
	// rejected for being over its total-storage cap. The relay adapter maps the relay's
	// ErrMailboxFull onto it so the send handler returns 507 rather than a generic 502.
	ErrMailboxFull = errors.New("recipient mailbox full")
	// ErrRecipientClosed: the recipient's account is closed and its relay refused the copy. Like
	// ErrMailboxFull it is the account's verdict, so the send answers 410 without failing over.
	ErrRecipientClosed = errors.New("recipient account closed")
	// ErrAccessSuspended / ErrAccessClosed: the account's node-enforced access entitlement
	// blocks reads. The relay adapter maps the relay's sentinels onto these so the mailbox
	// challenge returns 403 with a machine code the client shows as an account state.
	ErrAccessSuspended = errors.New("account access suspended")
	ErrAccessClosed    = errors.New("account access closed")
)

// RelayProxy is the relay-facing surface the mailbox endpoints need. Challenge issues a
// fresh single-use nonce the caller must sign to authorize an op for its mailbox; every
// other method takes the proof the browser made over that nonce and runs the op if the
// relay's gate accepts it. No private key leaves the browser: the server only holds the
// nonce between challenge and complete.
//
// The proof is the account key's signature and, once the mailbox has devices, an enrolled
// device's (relay.AuthorizeMailbox). A refusal the client acts on comes back as a
// *relay.OpError, and writeOpError turns its code into the response.
type RelayProxy interface {
	Challenge(ctx context.Context, address string) (nonce []byte, err error)
	List(ctx context.Context, address string, proof relay.MailboxProof, limit int, cursor []byte) (entries []*dmcnpb.MailboxEntry, next []byte, err error)
	Body(ctx context.Context, address string, proof relay.MailboxProof, hash [32]byte) (*dmcnpb.MailboxBody, error)
	Delete(ctx context.Context, address string, proof relay.MailboxProof, hash [32]byte) error
	// Personal storage: the owner's sealed per-account state (contacts, Sent, flags, labels,
	// settings). The relay only ever sees ciphertext.
	KvGet(ctx context.Context, address string, proof relay.MailboxProof, key string) (item relay.KvItem, found bool, err error)
	KvPut(ctx context.Context, address string, proof relay.MailboxProof, key string, sealed []byte, expectedVersion uint64) (version uint64, err error)
	KvList(ctx context.Context, address string, proof relay.MailboxProof, prefix string, limit int, cursor string, values bool) (items []relay.KvItem, next string, err error)
	KvDelete(ctx context.Context, address string, proof relay.MailboxProof, key string) error
	KvStat(ctx context.Context, address string, proof relay.MailboxProof) (used, quota, count uint64, err error)
	// The device registry. The op's own signatures (an approval, a retirement) are made over
	// the same nonce as the proof, which is why they arrive at completion and not before.
	DeviceEnroll(ctx context.Context, address string, proof relay.MailboxProof, op *dmcnpb.MailboxDeviceEnrollOp) (device *dmcnpb.DeviceRecord, genesis bool, err error)
	DeviceList(ctx context.Context, address string, proof relay.MailboxProof) ([]*dmcnpb.DeviceRecord, error)
	DeviceRetire(ctx context.Context, address string, proof relay.MailboxProof, op *dmcnpb.MailboxDeviceRetireOp) (*dmcnpb.DeviceRecord, error)
}

// pendingMailbox holds a challenge nonce + op parameters between the challenge and
// complete requests, tagged with the owning session address.
type pendingMailbox struct {
	address   string
	op        string
	limit     int
	cursor    []byte
	hash      [32]byte
	nonce     []byte
	expiresAt time.Time

	// Personal-storage parameters, carried across the challenge/complete pair like the mail
	// ones above so the browser signs a nonce bound to the operation it asked for.
	key             string
	prefix          string
	sealed          []byte
	expectedVersion uint64
	values          bool

	// Device registry: who is being enrolled or retired. Fixed at the challenge, so a
	// completion can only finish the op that was asked for.
	devicePub        []byte
	deviceLabel      []byte
	deviceCredential []byte
	recovery         bool
}

// pendingStore holds in-flight mailbox challenges keyed by a random correlation
// ID, with a background sweeper that drops challenges abandoned past their TTL.
type pendingStore struct {
	m sync.Map // correlationID → *pendingMailbox
}

func newPendingStore() *pendingStore {
	ps := &pendingStore{}
	go ps.sweep()
	return ps
}

func (ps *pendingStore) put(p *pendingMailbox) (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	ps.m.Store(id, p)
	return id, nil
}

func (ps *pendingStore) take(id string) (*pendingMailbox, bool) {
	v, ok := ps.m.LoadAndDelete(id)
	if !ok {
		return nil, false
	}
	return v.(*pendingMailbox), true
}

// sweep periodically drops challenges whose nonce expired without a matching
// complete (e.g. the client navigated away mid-op).
func (ps *pendingStore) sweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now()
		ps.m.Range(func(k, v any) bool {
			p := v.(*pendingMailbox)
			if now.After(p.expiresAt) {
				ps.m.Delete(k)
			}
			return true
		})
	}
}

// MailboxHandler backs the durable mailbox over plain REST: a two-phase
// challenge/complete exchange. The relay requires the client to sign a per-op
// nonce, so each op is a challenge (returns a nonce) followed by a complete (the
// client signs; the server finishes the relay op).
type MailboxHandler struct {
	relay   RelayProxy
	pending *pendingStore
	log     logr.Logger
}

// NewMailboxHandler builds a MailboxHandler and starts its pending-challenge sweeper.
func NewMailboxHandler(relay RelayProxy, log logr.Logger) *MailboxHandler {
	return &MailboxHandler{relay: relay, pending: newPendingStore(), log: log}
}

type mailboxChallengeRequest struct {
	Op     string `json:"op"`               // "list" | "body" | "delete" | "kv_*"
	Limit  int    `json:"limit,omitempty"`  // list page size (0 = relay default)
	Cursor string `json:"cursor,omitempty"` // base64; list continuation
	Hash   string `json:"hash,omitempty"`   // hex; body/delete target

	// Personal storage. The sealed blob is opaque to this backend and to the relay — the
	// browser seals it to the owner before it is ever sent.
	Key             string `json:"key,omitempty"`              // kv_get/kv_put/kv_delete target
	Prefix          string `json:"prefix,omitempty"`           // kv_list namespace, e.g. "contacts/"
	Sealed          string `json:"sealed,omitempty"`           // base64; kv_put payload
	ExpectedVersion uint64 `json:"expected_version,omitempty"` // kv_put CAS; 0 = unconditional
	Values          bool   `json:"values,omitempty"`           // kv_list: include blobs, not just keys

	// Device registry (device_enroll, device_retire). DevicePublic is the device being enrolled
	// or retired. The approving device's signature is not here: it covers the nonce this call
	// returns, so it arrives with the completion.
	DevicePublic     string `json:"device_public,omitempty"`     // base64
	DeviceLabel      string `json:"device_label,omitempty"`      // base64 SealedBlob, sealed to the owner
	DeviceCredential string `json:"device_credential,omitempty"` // base64 marshaled Credential
	Recovery         bool   `json:"recovery,omitempty"`          // device_enroll: join on the recovery delay
}

type mailboxChallengeResponse struct {
	CorrelationID string `json:"correlation_id"`
	Nonce         string `json:"nonce"` // base64
}

type mailboxCompleteRequest struct {
	CorrelationID string `json:"correlation_id"`
	// The account key over the challenge nonce, base64. May be empty on an operation an
	// enrolled device may perform by itself.
	Signature string `json:"signature,omitempty"`
	// The device half: this device's key, and its signature over the tagged nonce. Required by
	// the relay once the mailbox has devices.
	DevicePublic    string `json:"device_public,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
	// device_enroll and device_retire: the asking device's own authorization over the same
	// nonce, and for an enrolment the moment it attests the newcomer joined.
	ApproverSignature string `json:"approver_signature,omitempty"`
	ApprovedAt        int64  `json:"approved_at,omitempty"`
}

// mailboxEntryData is one header preview in a list result. Entry is the base64
// MailboxEntry protobuf, which the client decodes to decrypt + verify the header.
type mailboxEntryData struct {
	Hash  string `json:"hash"`  // hex
	Entry string `json:"entry"` // base64 protobuf (MailboxEntry)
}

type mailboxListResponse struct {
	Entries    []mailboxEntryData `json:"entries"`
	NextCursor string             `json:"next_cursor"` // base64; empty when drained
}

type mailboxBodyResponse struct {
	Hash string `json:"hash"` // hex
	Body string `json:"body"` // base64 protobuf (MailboxBody)
}

type mailboxDeletedResponse struct {
	Hash string `json:"hash"` // hex
}

// --- Personal-storage responses. Sealed blobs are base64 of ciphertext the server never reads.

type kvGetResponse struct {
	Found   bool   `json:"found"`
	Sealed  string `json:"sealed,omitempty"`
	Version uint64 `json:"version"`
	// The relay's own record of the write: when, and by which device (sealed to the owner).
	WrittenAt    int64  `json:"written_at,omitempty"`
	SealedWriter string `json:"sealed_writer,omitempty"`
}

type kvPutResponse struct {
	Version uint64 `json:"version"`
}

type kvItemData struct {
	Key          string `json:"key"`
	Sealed       string `json:"sealed,omitempty"`
	Version      uint64 `json:"version"`
	WrittenAt    int64  `json:"written_at,omitempty"`
	SealedWriter string `json:"sealed_writer,omitempty"`
}

type kvListResponse struct {
	Items      []kvItemData `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

type kvDeleteResponse struct {
	Deleted bool `json:"deleted"`
}

type kvStatResponse struct {
	UsedBytes  uint64 `json:"used_bytes"`
	QuotaBytes uint64 `json:"quota_bytes"`
	Count      uint64 `json:"count"`
}

// HandleChallenge issues a challenge nonce for a mailbox op on the caller's mailbox and
// returns a correlation ID to complete the op with.
func (h *MailboxHandler) HandleChallenge(w http.ResponseWriter, r *http.Request) {
	address := webcore.AddressFromContext(r.Context())
	if address == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req mailboxChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Op {
	case "list", "body", "delete", "kv_get", "kv_put", "kv_list", "kv_delete", "kv_stat",
		"device_enroll", "device_list", "device_retire":
	default:
		writeError(w, http.StatusBadRequest, "unknown mailbox op: "+req.Op)
		return
	}

	p := &pendingMailbox{
		address:         address,
		op:              req.Op,
		limit:           req.Limit,
		key:             req.Key,
		prefix:          req.Prefix,
		expectedVersion: req.ExpectedVersion,
		values:          req.Values,
		expiresAt:       time.Now().Add(30 * time.Second),
		recovery:        req.Op == "device_enroll" && req.Recovery,
	}
	for _, f := range []struct {
		in   string
		out  *[]byte
		what string
	}{
		{req.DevicePublic, &p.devicePub, "device key"},
		{req.DeviceLabel, &p.deviceLabel, "device label"},
		{req.DeviceCredential, &p.deviceCredential, "device credential"},
	} {
		if f.in == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(f.in)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid "+f.what+" encoding")
			return
		}
		*f.out = b
	}
	if (req.Op == "device_enroll" || req.Op == "device_retire") && len(p.devicePub) != 32 {
		writeError(w, http.StatusBadRequest, "device key must be 32 bytes")
		return
	}
	if req.Sealed != "" {
		blob, err := base64.StdEncoding.DecodeString(req.Sealed)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid sealed encoding")
			return
		}
		p.sealed = blob
	}
	if req.Cursor != "" {
		cur, err := base64.StdEncoding.DecodeString(req.Cursor)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor encoding")
			return
		}
		p.cursor = cur
	}
	if req.Op == "body" || req.Op == "delete" {
		hb, err := hex.DecodeString(req.Hash)
		if err != nil || len(hb) != 32 {
			writeError(w, http.StatusBadRequest, "invalid hash")
			return
		}
		copy(p.hash[:], hb)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	nonce, err := h.relay.Challenge(ctx, address)
	if err != nil {
		if errors.Is(err, ErrAccessSuspended) {
			writeErrorCode(w, http.StatusForbidden, "access_suspended", "account access is suspended")
			return
		}
		if errors.Is(err, ErrAccessClosed) {
			writeErrorCode(w, http.StatusForbidden, "access_closed", "account access is closed")
			return
		}
		h.log.Error("mailbox challenge failed", logr.M("address", address), logr.M("error", err.Error()))
		writeError(w, http.StatusBadGateway, "mailbox challenge failed: "+err.Error())
		return
	}
	p.nonce = nonce

	id, err := h.pending.put(p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to register challenge")
		return
	}

	writeJSON(w, http.StatusOK, mailboxChallengeResponse{
		CorrelationID: id,
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
	})
}

// HandleComplete finishes a mailbox op with the client's signature over the nonce
// and returns the relay result.
func (h *MailboxHandler) HandleComplete(w http.ResponseWriter, r *http.Request) {
	address := webcore.AddressFromContext(r.Context())
	if address == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req mailboxCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	p, ok := h.pending.take(req.CorrelationID)
	if !ok {
		writeError(w, http.StatusNotFound, "no pending mailbox op for this correlation id")
		return
	}
	if p.address != address {
		writeError(w, http.StatusForbidden, "correlation id does not belong to this session")
		return
	}
	if time.Now().After(p.expiresAt) {
		writeError(w, http.StatusGone, "mailbox challenge expired")
		return
	}

	proof := relay.MailboxProof{Nonce: p.nonce}
	var approverSig []byte
	for _, f := range []struct {
		in   string
		out  *[]byte
		what string
	}{
		{req.Signature, &proof.Signature, "signature"},
		{req.DevicePublic, &proof.DevicePublic, "device key"},
		{req.DeviceSignature, &proof.DeviceSignature, "device signature"},
		{req.ApproverSignature, &approverSig, "approver signature"},
	} {
		if f.in == "" {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(f.in)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid "+f.what+" encoding")
			return
		}
		*f.out = b
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	switch p.op {
	case "list":
		entries, next, err := h.relay.List(ctx, p.address, proof, p.limit, p.cursor)
		if err != nil {
			h.writeOpError(w, "mailbox list", err)
			return
		}
		out := make([]mailboxEntryData, 0, len(entries))
		for _, e := range entries {
			b, mErr := proto.Marshal(e)
			if mErr != nil {
				h.log.Error("marshal mailbox entry", logr.M("error", mErr.Error()))
				continue
			}
			out = append(out, mailboxEntryData{
				Hash:  hex.EncodeToString(e.Hash),
				Entry: base64.StdEncoding.EncodeToString(b),
			})
		}
		writeJSON(w, http.StatusOK, mailboxListResponse{Entries: out, NextCursor: base64.StdEncoding.EncodeToString(next)})

	case "body":
		body, err := h.relay.Body(ctx, p.address, proof, p.hash)
		if err != nil {
			h.writeOpError(w, "mailbox body", err)
			return
		}
		b, mErr := proto.Marshal(body)
		if mErr != nil {
			writeError(w, http.StatusInternalServerError, "marshal body failed")
			return
		}
		writeJSON(w, http.StatusOK, mailboxBodyResponse{
			Hash: hex.EncodeToString(p.hash[:]),
			Body: base64.StdEncoding.EncodeToString(b),
		})

	case "delete":
		if err := h.relay.Delete(ctx, p.address, proof, p.hash); err != nil {
			h.writeOpError(w, "mailbox delete", err)
			return
		}
		writeJSON(w, http.StatusOK, mailboxDeletedResponse{Hash: hex.EncodeToString(p.hash[:])})

	case "kv_get":
		it, found, err := h.relay.KvGet(ctx, p.address, proof, p.key)
		if err != nil {
			h.writeOpError(w, "mailbox storage get", err)
			return
		}
		writeJSON(w, http.StatusOK, kvGetResponse{
			Found: found, Version: it.Version, Sealed: base64.StdEncoding.EncodeToString(it.Sealed),
			WrittenAt: it.WrittenAt, SealedWriter: base64.StdEncoding.EncodeToString(it.SealedWriter),
		})

	case "kv_put":
		version, err := h.relay.KvPut(ctx, p.address, proof, p.key, p.sealed, p.expectedVersion)
		if err != nil {
			h.writeOpError(w, "mailbox storage put", err)
			return
		}
		writeJSON(w, http.StatusOK, kvPutResponse{Version: version})

	case "kv_list":
		items, next, err := h.relay.KvList(ctx, p.address, proof, p.prefix, p.limit, string(p.cursor), p.values)
		if err != nil {
			h.writeOpError(w, "mailbox storage list", err)
			return
		}
		out := make([]kvItemData, 0, len(items))
		for _, it := range items {
			out = append(out, kvItemData{
				Key: it.Key, Version: it.Version,
				Sealed:    base64.StdEncoding.EncodeToString(it.Sealed),
				WrittenAt: it.WrittenAt, SealedWriter: base64.StdEncoding.EncodeToString(it.SealedWriter),
			})
		}
		writeJSON(w, http.StatusOK, kvListResponse{Items: out, NextCursor: next})

	case "kv_delete":
		if err := h.relay.KvDelete(ctx, p.address, proof, p.key); err != nil {
			h.writeOpError(w, "mailbox storage delete", err)
			return
		}
		writeJSON(w, http.StatusOK, kvDeleteResponse{Deleted: true})

	case "kv_stat":
		used, quota, count, err := h.relay.KvStat(ctx, p.address, proof)
		if err != nil {
			h.writeOpError(w, "mailbox storage stat", err)
			return
		}
		writeJSON(w, http.StatusOK, kvStatResponse{UsedBytes: used, QuotaBytes: quota, Count: count})

	case "device_enroll":
		// The approving device is the one that proved itself at the gate: one key signs both,
		// so a device can't vouch for another while authenticating as a third. It is named only
		// where there is an approval to name it for. A first device proves itself with the key
		// it is enrolling, and that isn't an approver.
		op := &dmcnpb.MailboxDeviceEnrollOp{
			Ed25519PublicKey: p.devicePub,
			SealedLabel:      p.deviceLabel,
			DeviceCredential: p.deviceCredential,
			Recovery:         p.recovery,
		}
		if len(approverSig) > 0 {
			op.ApproverEd25519PublicKey = proof.DevicePublic
			op.ApproverSignature = approverSig
			op.ApprovedAt = req.ApprovedAt
		}
		device, genesis, err := h.relay.DeviceEnroll(ctx, p.address, proof, op)
		if err != nil {
			h.writeOpError(w, "device enrol", err)
			return
		}
		writeJSON(w, http.StatusOK, deviceEnrollResponse{Device: deviceData(device), Genesis: genesis})

	case "device_list":
		devices, err := h.relay.DeviceList(ctx, p.address, proof)
		if err != nil {
			h.writeOpError(w, "device list", err)
			return
		}
		out := make([]deviceRecordData, 0, len(devices))
		for _, d := range devices {
			out = append(out, deviceData(d))
		}
		writeJSON(w, http.StatusOK, deviceListResponse{Devices: out})

	case "device_retire":
		device, err := h.relay.DeviceRetire(ctx, p.address, proof, &dmcnpb.MailboxDeviceRetireOp{
			Ed25519PublicKey:       p.devicePub,
			SignerEd25519PublicKey: proof.DevicePublic,
			SignerSignature:        approverSig,
		})
		if err != nil {
			h.writeOpError(w, "device retire", err)
			return
		}
		writeJSON(w, http.StatusOK, deviceRetireResponse{Device: deviceData(device)})
	}
}

// deviceRecordData is one device as the client sees it. The label stays sealed: the server
// can't read what the owner calls their devices.
type deviceRecordData struct {
	Public      string `json:"public"` // base64 Ed25519
	EnrolledAt  int64  `json:"enrolled_at"`
	RetiredAt   int64  `json:"retired_at,omitempty"`
	EligibleAt  int64  `json:"eligible_at,omitempty"` // set while a recovery enrolment waits
	Credential  string `json:"credential,omitempty"`  // the domain's attestation, if one was supplied
	SealedLabel string `json:"sealed_label,omitempty"`
}

func deviceData(d *dmcnpb.DeviceRecord) deviceRecordData {
	if d == nil {
		return deviceRecordData{}
	}
	return deviceRecordData{
		Public:      base64.StdEncoding.EncodeToString(d.GetEd25519PublicKey()),
		EnrolledAt:  d.GetEnrolledAt(),
		RetiredAt:   d.GetRetiredAt(),
		EligibleAt:  d.GetEligibleAt(),
		Credential:  base64.StdEncoding.EncodeToString(d.GetDeviceCredential()),
		SealedLabel: base64.StdEncoding.EncodeToString(d.GetSealedLabel()),
	}
}

type deviceEnrollResponse struct {
	Device deviceRecordData `json:"device"`
	// Genesis reports that this enrolment created the registry.
	Genesis bool `json:"genesis"`
}

type deviceListResponse struct {
	Devices []deviceRecordData `json:"devices"`
}

type deviceRetireResponse struct {
	Device deviceRecordData `json:"device"`
}

// opErrorStatus is the HTTP answer to each refusal a client acts on. The code in the body is
// the relay's own, lowercased: a client branches on that and never on the sentence beside it.
//
// None of these is 401. A session that is refused at the mailbox gate is still a valid
// session, and a client that re-authenticated on it would loop.
var opErrorStatus = map[string]int{
	"AUTH_FAILED":              http.StatusForbidden,
	"DEVICE_NOT_ENROLLED":      http.StatusForbidden,
	"DEVICE_APPROVAL_REQUIRED": http.StatusForbidden,
	"DEVICE_ON_PROBATION":      http.StatusForbidden,
	"DEVICE_RECOVERY_DISABLED": http.StatusForbidden,
	"DEVICE_ALREADY_ENROLLED":  http.StatusConflict,
	"INVALID_REQUEST":          http.StatusBadRequest,
	"UNSUPPORTED":              http.StatusNotImplemented,
}

// writeOpError answers a failed mailbox op. A refusal with a code keeps it; a storage failure
// keeps the statuses a client already acts on; anything else is a 502.
func (h *MailboxHandler) writeOpError(w http.ResponseWriter, what string, err error) {
	var oe *relay.OpError
	if errors.As(err, &oe) {
		if status, ok := opErrorStatus[oe.Code]; ok {
			writeErrorCode(w, status, strings.ToLower(oe.Code), oe.Message)
			return
		}
	}
	msg := err.Error()
	switch {
	case errors.Is(err, relay.ErrKvUnsupported) || strings.Contains(msg, "does not host personal storage"):
		writeErrorCode(w, http.StatusNotImplemented, "storage_unsupported", msg)
	case errors.Is(err, relay.ErrKvConflict) || strings.Contains(msg, "version conflict"):
		writeErrorCode(w, http.StatusConflict, "storage_conflict", msg)
	case errors.Is(err, relay.ErrQuotaExceeded) || strings.Contains(msg, "quota"):
		writeErrorCode(w, http.StatusInsufficientStorage, "storage_quota", msg)
	case errors.Is(err, relay.ErrKvBadKey):
		writeErrorCode(w, http.StatusBadRequest, "storage_bad_key", msg)
	default:
		writeError(w, http.StatusBadGateway, what+" failed: "+msg)
	}
}
