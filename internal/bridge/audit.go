package bridge

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

// AuditEvent is one entry in the bridge's accountability trail: an inbound
// classification decision or an outbound delivery outcome.
type AuditEvent struct {
	Time      time.Time       `json:"time"`
	Action    string          `json:"action"` // e.g. inbound.deliver, inbound.reject, outbound.deliver, outbound.reject
	From      string          `json:"from,omitempty"`
	To        string          `json:"to,omitempty"`
	SenderIP  string          `json:"sender_ip,omitempty"`
	TrustTier BridgeTrustTier `json:"trust_tier,omitempty"`
	Success   bool            `json:"success"`
	Detail    string          `json:"detail,omitempty"`
}

// AuditLog records bridge audit events. Implementations must be safe for
// concurrent use and must not block the calling path for long.
type AuditLog interface {
	Record(ev AuditEvent)
}

// nopAuditLog discards events; the default when no audit log is configured.
type nopAuditLog struct{}

func (nopAuditLog) Record(AuditEvent) {}

// auditRecord is the on-disk, tamper-evident form of an event. Records form a
// hash chain: each commits to the previous record's hash, and Hash is signed by
// the bridge key. Editing, reordering, deleting, or rewriting any record breaks
// either the chain or a signature, and is caught by VerifyAuditLog using the
// bridge's (out-of-band) public key.
type auditRecord struct {
	Seq      uint64 `json:"seq"`
	PrevHash string `json:"prev,omitempty"`
	AuditEvent
	Hash string `json:"hash,omitempty"`
	Sig  string `json:"sig,omitempty"` // Ed25519 over the Hash bytes, hex
}

// chainHash computes the record's hash over its canonical bytes (everything
// except Hash and Sig) — which already includes Seq and PrevHash, linking the
// chain.
func (r auditRecord) chainHash() ([]byte, error) {
	r.Hash, r.Sig = "", ""
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// FileAuditLog appends hash-chained, signed JSON records to a file opened
// O_APPEND. The chain head (last seq + hash) is recovered on open so appends
// continue an existing log.
type FileAuditLog struct {
	mu       sync.Mutex
	f        *os.File
	signKey  ed25519.PrivateKey
	lastSeq  uint64
	lastHash string
	log      logr.Logger
}

// NewFileAuditLog opens (creating if needed) an append-only audit log at path,
// continuing any existing hash chain. signKey signs each record; if nil, records
// are hash-chained but unsigned.
func NewFileAuditLog(path string, signKey ed25519.PrivateKey, log logr.Logger) (*FileAuditLog, error) {
	seq, head, err := scanChainHead(path, log)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileAuditLog{f: f, signKey: signKey, lastSeq: seq, lastHash: head, log: log}, nil
}

// scanChainHead reads an existing log and returns the last record's seq and hash
// (0, "" for a new/empty log) so new appends continue the chain.
func scanChainHead(path string, log logr.Logger) (uint64, string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	var lastSeq uint64
	var lastHash string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			log.Warnf("audit: skipping unparseable line while recovering chain head: %v", err)
			continue
		}
		lastSeq, lastHash = rec.Seq, rec.Hash
	}
	if err := sc.Err(); err != nil {
		return 0, "", fmt.Errorf("audit: scan existing log: %w", err)
	}
	return lastSeq, lastHash, nil
}

// Record links the event into the chain, signs it, and appends it. Failures are
// logged but never propagate — auditing must not break mail handling.
func (a *FileAuditLog) Record(ev AuditEvent) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	rec := auditRecord{Seq: a.lastSeq + 1, PrevHash: a.lastHash, AuditEvent: ev}
	hash, err := rec.chainHash()
	if err != nil {
		a.log.Warnf("audit: hash event: %v", err)
		return
	}
	rec.Hash = hex.EncodeToString(hash)
	if a.signKey != nil {
		sig, err := crypto.Sign(a.signKey, hash)
		if err != nil {
			a.log.Warnf("audit: sign event: %v", err)
			return
		}
		rec.Sig = hex.EncodeToString(sig)
	}

	line, err := json.Marshal(rec)
	if err != nil {
		a.log.Warnf("audit: marshal record: %v", err)
		return
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		a.log.Warnf("audit: write record: %v", err)
		return
	}
	a.lastSeq, a.lastHash = rec.Seq, rec.Hash
}

// Close closes the underlying file.
func (a *FileAuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}

// ErrAuditTampered is returned by VerifyAuditLog when the chain or a signature
// fails to verify.
var ErrAuditTampered = errors.New("bridge: audit log integrity check failed")

// VerifyAuditLog re-reads a hash-chained audit log and verifies its integrity:
// sequence numbers are contiguous from 1, each record links to the previous
// record's hash, each Hash matches a recompute, and (when pub is non-nil) each
// record's signature verifies against pub. It returns the number of records
// verified, or wraps ErrAuditTampered at the first broken record.
//
// Tamper-evidence holds against any holder WITHOUT the bridge private key:
// editing/reordering/deleting a record breaks the chain or a signature. A full
// rewrite is caught by the signature check (the attacker cannot re-sign). The
// caller must supply pub from a trusted source (e.g. the bridge keystore), never
// from the log file itself. End-truncation is not detectable without an external
// head anchor.
func VerifyAuditLog(path string, pub ed25519.PublicKey) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var count, prevSeq uint64
	prevHash := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec auditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return count, fmt.Errorf("%w: record %d: unparseable: %v", ErrAuditTampered, prevSeq+1, err)
		}
		if rec.Seq != prevSeq+1 {
			return count, fmt.Errorf("%w: expected seq %d, got %d", ErrAuditTampered, prevSeq+1, rec.Seq)
		}
		if rec.PrevHash != prevHash {
			return count, fmt.Errorf("%w: record %d prev-hash does not chain", ErrAuditTampered, rec.Seq)
		}
		want, err := rec.chainHash()
		if err != nil {
			return count, fmt.Errorf("%w: record %d rehash: %v", ErrAuditTampered, rec.Seq, err)
		}
		if hex.EncodeToString(want) != rec.Hash {
			return count, fmt.Errorf("%w: record %d hash mismatch (edited)", ErrAuditTampered, rec.Seq)
		}
		if pub != nil {
			sig, err := hex.DecodeString(rec.Sig)
			if err != nil {
				return count, fmt.Errorf("%w: record %d bad signature encoding", ErrAuditTampered, rec.Seq)
			}
			if err := crypto.Verify(pub, want, sig); err != nil {
				return count, fmt.Errorf("%w: record %d signature invalid", ErrAuditTampered, rec.Seq)
			}
		}
		prevSeq, prevHash = rec.Seq, rec.Hash
		count++
	}
	if err := sc.Err(); err != nil {
		return count, err
	}
	return count, nil
}
