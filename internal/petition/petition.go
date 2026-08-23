// Package petition implements the mailbox petition queue: the way a person gets an address on
// a live self-hosted domain without the domain root key ever being on the node.
//
// The problem it solves is ordering. A domain's root key signs the credential that binds an
// address to a keypair, and that key stays offline — so the node cannot mint addresses, and
// self-service registration (which is what dev mode does) cannot exist here. The obvious
// alternative, having the admin generate a keypair and send it to the user, is worse: it puts
// the user's private key on a second machine and then on whatever channel carries it.
//
// So the key never moves and the address is assigned to it instead:
//
//  1. The browser generates the keypair, keeps it, and sends only the public half plus a
//     signature proving possession. The node answers with a 12-digit code.
//  2. The petitioner reads that code to the admin out of band. Having a way to reach the admin
//     IS the authorization gate — there is no ACL, no allowlist, and no open queue to triage.
//  3. The admin looks the petition up BY CODE (never by browsing), picks an address, and signs
//     the credentials for it with the offline root.
//  4. The browser learns its address by polling, self-signs its record, and the node publishes
//     it with the credentials the admin left behind.
//
// The petitioner cannot choose an address. That is the load-bearing property: there is nothing
// to squat, so an unclaimed petition is worth nothing to whoever filed it and can simply
// expire. Everything here is local to the node and never published.
package petition

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// DefaultTTL is how long an unclaimed petition survives. It bounds the window in which a
// leaked code is worth anything, so it wants to be short; but the step it has to cover is a
// human telling another human twelve digits, which may be a message left overnight or across a
// timezone. A day covers that without leaving a standing queue.
const DefaultTTL = 24 * time.Hour

// maxPending caps the queue. The create endpoint is public and unauthenticated by design —
// anyone who can reach the daemon can file one — so rate limiting alone bounds the RATE of
// junk, not the total. Since no petition is worth anything until an admin acts on a code they
// were told out of band, dropping new ones past the cap costs a legitimate user a retry and
// costs an attacker their whole flood.
const maxPending = 256

// sigContext domain-separates the possession proof, so a signature made here can never be
// replayed as a signature over anything else the owner key signs.
const sigContext = "dmcn-petition-v1\x00"

var (
	ErrNotFound  = errors.New("petition: no such petition")
	ErrExpired   = errors.New("petition: expired")
	ErrAssigned  = errors.New("petition: already assigned")
	ErrPending   = errors.New("petition: not yet assigned")
	ErrQueueFull = errors.New("petition: queue is full")
	ErrBadProof  = errors.New("petition: signature does not prove possession of the key")
)

// Petition is one pending request for a mailbox. It holds no private key and is never
// published: it lives only in the node's data dir until it is completed or expires.
type Petition struct {
	Code          string            `json:"code"`
	Ed25519Public ed25519.PublicKey `json:"ed25519_public"`
	X25519Public  [32]byte          `json:"x25519_public"`
	CreatedAt     time.Time         `json:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at"`

	// Set once the admin has assigned an address. The two credentials are signed by the
	// offline root on the admin's machine and parked here until the browser comes back with a
	// self-signed record to attach them to — the record cannot exist before this point,
	// because the owner self-signature covers the address.
	Address           string               `json:"address,omitempty"`
	AssignedAt        time.Time            `json:"assigned_at,omitempty"`
	AddressCredential *identity.Credential `json:"-"`
	RoutingCredential *identity.Credential `json:"-"`

	// Wire copies of the two credentials, so the queue survives a restart. Credential has no
	// JSON form of its own; these are its protobuf encoding.
	AddressCredentialPB []byte `json:"address_credential_pb,omitempty"`
	RoutingCredentialPB []byte `json:"routing_credential_pb,omitempty"`
}

// Assigned reports whether an admin has already given this petition an address.
func (p *Petition) Assigned() bool { return p.Address != "" }

// Expired reports whether the petition has aged out.
func (p *Petition) Expired(now time.Time) bool { return now.After(p.ExpiresAt) }

// SignableBytes is what a petitioner signs to prove they hold the Ed25519 private key. It
// binds the X25519 key too, so the pair that arrives is the pair that was proven — otherwise a
// petition could carry someone else's encryption key and mail sealed to the resulting address
// would be readable by them.
func SignableBytes(edPub ed25519.PublicKey, xPub [32]byte) []byte {
	b := make([]byte, 0, len(sigContext)+len(edPub)+32)
	b = append(b, sigContext...)
	b = append(b, edPub...)
	b = append(b, xPub[:]...)
	return b
}

// VerifyProof checks the possession proof over the two public keys.
func VerifyProof(edPub ed25519.PublicKey, xPub [32]byte, sig []byte) error {
	if len(edPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: ed25519 key is %d bytes, want %d", ErrBadProof, len(edPub), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(edPub, SignableBytes(edPub, xPub), sig) {
		return ErrBadProof
	}
	return nil
}

// NewCode returns a fresh 12-digit code in the same three-group shape as the device-pairing
// confirmation code ("0428-9173-5560"), which people have already been asked to read aloud.
//
// Unlike that one this is RANDOM rather than derived from the keys. A derived code would let
// someone who overheard a code grind a keypair that hashes to it and file a petition the admin
// would then assign an address to; 48 bits is well within reach. Nothing here needs the code to
// be bound to the keys — it is a rendezvous token, and the possession proof does the binding.
func NewCode() (string, error) {
	b, err := crypto.RandomBytes(8)
	if err != nil {
		return "", fmt.Errorf("petition: generate code: %w", err)
	}
	n := binary.BigEndian.Uint64(b) % 1_000_000_000_000
	s := fmt.Sprintf("%012d", n)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12], nil
}

// Store is the node's petition queue, persisted as JSON in the data dir.
//
// It is deliberately a plain file rather than the node's leveldb: the queue holds at most a
// few hundred short-lived entries, it is daemon-local operator state rather than anything the
// protocol knows about, and reaching it through the node would mean widening the node's API
// for something no other caller wants.
type Store struct {
	mu     sync.Mutex
	path   string
	ttl    time.Duration
	byCode map[string]*Petition
}

// NewStore opens (or creates) the queue at path. Entries already past their TTL are dropped on
// load, so a daemon that was down over a weekend does not come back holding stale petitions.
func NewStore(path string, ttl time.Duration) (*Store, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	s := &Store{path: path, ttl: ttl, byCode: map[string]*Petition{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now())
	return s, s.saveLocked()
}

// TTL reports the configured lifetime, for operator-facing output.
func (s *Store) TTL() time.Duration { return s.ttl }

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("petition: read %s: %w", s.path, err)
	}
	var list []*Petition
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("petition: parse %s: %w", s.path, err)
	}
	for _, p := range list {
		// Rehydrate the credentials from their wire copies. A petition whose credentials no
		// longer parse is dropped rather than served half-assigned.
		if len(p.AddressCredentialPB) > 0 {
			c, cerr := identity.CredentialFromProtoBytes(p.AddressCredentialPB)
			if cerr != nil {
				continue
			}
			p.AddressCredential = c
		}
		if len(p.RoutingCredentialPB) > 0 {
			c, cerr := identity.CredentialFromProtoBytes(p.RoutingCredentialPB)
			if cerr != nil {
				continue
			}
			p.RoutingCredential = c
		}
		s.byCode[p.Code] = p
	}
	return nil
}

func (s *Store) saveLocked() error {
	list := make([]*Petition, 0, len(s.byCode))
	for _, p := range s.byCode {
		list = append(list, p)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("petition: encode queue: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("petition: create queue dir: %w", err)
	}
	// Write-then-rename, so a crash mid-write cannot leave a truncated queue behind.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("petition: write queue: %w", err)
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) pruneLocked(now time.Time) int {
	n := 0
	for code, p := range s.byCode {
		if p.Expired(now) {
			delete(s.byCode, code)
			n++
		}
	}
	return n
}

// Prune drops expired petitions and reports how many went.
func (s *Store) Prune(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.pruneLocked(now)
	if n == 0 {
		return 0, nil
	}
	return n, s.saveLocked()
}

// Create files a new petition for a proven keypair and returns it with its fresh code.
func (s *Store) Create(edPub ed25519.PublicKey, xPub [32]byte, sig []byte, now time.Time) (*Petition, error) {
	if err := VerifyProof(edPub, xPub, sig); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.byCode) >= maxPending {
		return nil, ErrQueueFull
	}

	// A collision would hand the admin someone else's petition, so retry rather than trust
	// 10^12 to be roomy enough.
	var code string
	for i := 0; i < 8; i++ {
		c, err := NewCode()
		if err != nil {
			return nil, err
		}
		if _, taken := s.byCode[c]; !taken {
			code = c
			break
		}
	}
	if code == "" {
		return nil, fmt.Errorf("petition: could not find an unused code")
	}

	p := &Petition{
		Code:          code,
		Ed25519Public: append(ed25519.PublicKey(nil), edPub...),
		X25519Public:  xPub,
		CreatedAt:     now.UTC(),
		ExpiresAt:     now.UTC().Add(s.ttl),
	}
	s.byCode[code] = p
	return p, s.saveLocked()
}

// Get returns the petition for code. An expired one is reported as not found: it is gone as far
// as every caller is concerned, whether or not the prune has run yet.
func (s *Store) Get(code string, now time.Time) (*Petition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byCode[code]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Expired(now) {
		delete(s.byCode, code)
		_ = s.saveLocked()
		return nil, ErrNotFound
	}
	return p, nil
}

// FindByKey returns the live petition already filed for a public key, if there is one. The
// daemon uses it so that re-filing for its own bridge identity across restarts reuses the
// pending petition rather than handing the operator a new code every time it boots.
func (s *Store) FindByKey(edPub ed25519.PublicKey, now time.Time) (*Petition, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	for _, p := range s.byCode {
		if p.Ed25519Public.Equal(edPub) {
			return p, true
		}
	}
	return nil, false
}

// Assign records the admin's decision: the address, and the two root-signed credentials that
// will be attached to the record when the browser comes back with it.
//
// Assignment happens once. A second assign on the same code fails rather than re-pointing it,
// so a code that has already been spent cannot be redirected to a different address by anyone
// who later learns it.
func (s *Store) Assign(code, address string, addrCred, routeCred *identity.Credential, now time.Time) (*Petition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.byCode[code]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Expired(now) {
		delete(s.byCode, code)
		_ = s.saveLocked()
		return nil, ErrExpired
	}
	if p.Assigned() {
		return nil, ErrAssigned
	}

	acPB, err := marshalCred(addrCred)
	if err != nil {
		return nil, err
	}
	rcPB, err := marshalCred(routeCred)
	if err != nil {
		return nil, err
	}
	p.Address = address
	p.AssignedAt = now.UTC()
	p.AddressCredential, p.AddressCredentialPB = addrCred, acPB
	p.RoutingCredential, p.RoutingCredentialPB = routeCred, rcPB
	return p, s.saveLocked()
}

// Complete removes a petition once its record has been published. The queue is not a directory
// — the published record is — so a completed petition has nothing left to say.
func (s *Store) Complete(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byCode[code]; !ok {
		return ErrNotFound
	}
	delete(s.byCode, code)
	return s.saveLocked()
}

// Pending reports how many petitions are currently queued, for operator-facing output.
func (s *Store) Pending(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	return len(s.byCode)
}

func marshalCred(c *identity.Credential) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("petition: missing credential")
	}
	b, err := proto.Marshal(c.ToProto())
	if err != nil {
		return nil, fmt.Errorf("petition: encode credential: %w", err)
	}
	return b, nil
}
