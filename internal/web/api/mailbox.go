package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
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
	Op     string `json:"op"`               // "list" | "body" | "delete"
	Limit  int    `json:"limit,omitempty"`  // list page size (0 = relay default)
	Cursor string `json:"cursor,omitempty"` // base64; list continuation
	Hash   string `json:"hash,omitempty"`   // hex; body/delete target
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
	case "list", "body", "delete":
	default:
		writeError(w, http.StatusBadRequest, "unknown mailbox op: "+req.Op)
		return
	}

	p := &pendingMailbox{
		address:   address,
		op:        req.Op,
		limit:     req.Limit,
		expiresAt: time.Now().Add(30 * time.Second),
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
	}
}
