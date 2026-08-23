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

// NOTE (open-dmcn reference implementation): the mail-filter and personal-KV ops
// (get_filter/put_filter, storage_*) rode the product mailbox-ext protocol and are
// omitted. Per-account state (Sent/contacts/flags/labels/settings) lives in the
// browser's IndexedDB. The core mailbox surface is list / body / delete.
//
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
	// ErrAccessSuspended / ErrAccessClosed: the account's node-enforced access entitlement
	// blocks reads. The relay adapter maps the relay's sentinels onto these so the mailbox
	// challenge returns 403 with a machine code the client shows as an account state.
	ErrAccessSuspended = errors.New("account access suspended")
	ErrAccessClosed    = errors.New("account access closed")
)

// RelayProxy is the relay-facing surface the mailbox endpoints need. Challenge issues a
// fresh single-use nonce the caller must sign to authorize an op for its mailbox; the
// List/Body/Delete methods verify that signature (against the address's record) and run
// the op. The private key never leaves the browser — the server only holds the nonce
// between challenge and complete.
type RelayProxy interface {
	Challenge(ctx context.Context, address string) (nonce []byte, err error)
	List(ctx context.Context, address string, nonce, signature []byte, limit int, cursor []byte) (entries []*dmcnpb.MailboxEntry, next []byte, err error)
	Body(ctx context.Context, address string, nonce, signature []byte, hash [32]byte) (*dmcnpb.MailboxBody, error)
	Delete(ctx context.Context, address string, nonce, signature []byte, hash [32]byte) error
	// Personal storage: the owner's sealed per-account state (contacts, Sent, flags, labels,
	// settings). The relay only ever sees ciphertext.
	KvGet(ctx context.Context, address string, nonce, signature []byte, key string) (sealed []byte, version uint64, found bool, err error)
	KvPut(ctx context.Context, address string, nonce, signature []byte, key string, sealed []byte, expectedVersion uint64) (version uint64, err error)
	KvList(ctx context.Context, address string, nonce, signature []byte, prefix string, limit int, cursor string, values bool) (items []relay.KvItem, next string, err error)
	KvDelete(ctx context.Context, address string, nonce, signature []byte, key string) error
	KvStat(ctx context.Context, address string, nonce, signature []byte) (used, quota, count uint64, err error)
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
}

type mailboxChallengeResponse struct {
	CorrelationID string `json:"correlation_id"`
	Nonce         string `json:"nonce"` // base64
}

type mailboxCompleteRequest struct {
	CorrelationID string `json:"correlation_id"`
	Signature     string `json:"signature"` // base64 (over the challenge nonce)
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
}

type kvPutResponse struct {
	Version uint64 `json:"version"`
}

type kvItemData struct {
	Key     string `json:"key"`
	Sealed  string `json:"sealed,omitempty"`
	Version uint64 `json:"version"`
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
	case "list", "body", "delete", "kv_get", "kv_put", "kv_list", "kv_delete", "kv_stat":
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

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	switch p.op {
	case "list":
		entries, next, err := h.relay.List(ctx, p.address, p.nonce, signature, p.limit, p.cursor)
		if err != nil {
			writeError(w, http.StatusBadGateway, "mailbox list failed: "+err.Error())
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
		body, err := h.relay.Body(ctx, p.address, p.nonce, signature, p.hash)
		if err != nil {
			writeError(w, http.StatusBadGateway, "mailbox body failed: "+err.Error())
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
		if err := h.relay.Delete(ctx, p.address, p.nonce, signature, p.hash); err != nil {
			writeError(w, http.StatusBadGateway, "mailbox delete failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, mailboxDeletedResponse{Hash: hex.EncodeToString(p.hash[:])})

	case "kv_get":
		sealed, version, found, err := h.relay.KvGet(ctx, p.address, p.nonce, signature, p.key)
		if err != nil {
			h.writeKvError(w, "get", err)
			return
		}
		writeJSON(w, http.StatusOK, kvGetResponse{
			Found: found, Version: version, Sealed: base64.StdEncoding.EncodeToString(sealed),
		})

	case "kv_put":
		version, err := h.relay.KvPut(ctx, p.address, p.nonce, signature, p.key, p.sealed, p.expectedVersion)
		if err != nil {
			h.writeKvError(w, "put", err)
			return
		}
		writeJSON(w, http.StatusOK, kvPutResponse{Version: version})

	case "kv_list":
		items, next, err := h.relay.KvList(ctx, p.address, p.nonce, signature, p.prefix, p.limit, string(p.cursor), p.values)
		if err != nil {
			h.writeKvError(w, "list", err)
			return
		}
		out := make([]kvItemData, 0, len(items))
		for _, it := range items {
			out = append(out, kvItemData{
				Key: it.Key, Version: it.Version,
				Sealed: base64.StdEncoding.EncodeToString(it.Sealed),
			})
		}
		writeJSON(w, http.StatusOK, kvListResponse{Items: out, NextCursor: next})

	case "kv_delete":
		if err := h.relay.KvDelete(ctx, p.address, p.nonce, signature, p.key); err != nil {
			h.writeKvError(w, "delete", err)
			return
		}
		writeJSON(w, http.StatusOK, kvDeleteResponse{Deleted: true})

	case "kv_stat":
		used, quota, count, err := h.relay.KvStat(ctx, p.address, p.nonce, signature)
		if err != nil {
			h.writeKvError(w, "stat", err)
			return
		}
		writeJSON(w, http.StatusOK, kvStatResponse{UsedBytes: used, QuotaBytes: quota, Count: count})
	}
}

// writeKvError maps a storage failure to a status the client can act on rather than a blanket
// 502. The distinctions matter to the caller: a conflict means re-read and retry, a full quota
// means delete something, and UNSUPPORTED means this relay has no personal storage at all and the
// client should fall back to keeping state locally instead of retrying forever.
func (h *MailboxHandler) writeKvError(w http.ResponseWriter, op string, err error) {
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
		writeError(w, http.StatusBadGateway, "mailbox storage "+op+" failed: "+msg)
	}
}
