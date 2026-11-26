package webcore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// ErrSessionNotFound is returned when a token is malformed or its signature
	// does not verify.
	ErrSessionNotFound = errors.New("webcore: session token invalid")
	// ErrSessionExpired is returned when a token's exp claim is in the past.
	ErrSessionExpired = errors.New("webcore: session expired")
	// ErrSessionRevoked is returned when a token was revoked (logged out) before
	// its natural expiry.
	ErrSessionRevoked = errors.New("webcore: session revoked")
)

// SessionStore issues and validates stateless HS256 JWT session tokens. The happy
// path holds no per-session server state — tokens carry their own claims and
// survive restarts as long as the signing secret is stable. The only state is a
// small persisted denylist of tokens revoked (via logout) before they expire;
// entries are pruned once expired, since the token is invalid by then anyway.
type SessionStore struct {
	secret   []byte
	ttl      time.Duration
	registry *revokeRegistry
}

// NewSessionStore creates a JWT session store. secret is the HMAC-SHA256 signing
// key (persist it so tokens survive restarts). ttl defaults to 24h when ≤ 0.
// revokedPath persists the revocation denylist; "" keeps it in-memory only.
func NewSessionStore(secret []byte, ttl time.Duration, revokedPath string) (*SessionStore, error) {
	if len(secret) == 0 {
		return nil, errors.New("webcore: session signing secret required")
	}
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	reg, err := newRevokeRegistry(revokedPath)
	if err != nil {
		return nil, err
	}
	return &SessionStore{secret: secret, ttl: ttl, registry: reg}, nil
}

// jwtClaims is the token payload (registered claims subset + jti for revocation).
type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti"`
}

// Create issues a signed JWT for the address, valid for the store's lifetime.
func (s *SessionStore) Create(address string) (string, error) {
	return s.CreateFor(address, s.ttl)
}

// CreateFor issues a signed JWT for the address that lasts ttl, for a session that must not
// outlive what it stands for (a device-pairing session ends with its throwaway identity).
func (s *SessionStore) CreateFor(address string, ttl time.Duration) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("webcore: generate jti: %w", err)
	}
	now := time.Now()
	return s.sign(jwtClaims{
		Sub: address,
		Iat: now.Unix(),
		Exp: now.Add(ttl).Unix(),
		Jti: hex.EncodeToString(jti),
	})
}

// Validate verifies a token's signature and expiry and that it has not been
// revoked, returning the address (sub claim).
func (s *SessionStore) Validate(token string) (string, error) {
	claims, err := s.verify(token)
	if err != nil {
		return "", ErrSessionNotFound
	}
	if time.Now().Unix() > claims.Exp {
		return "", ErrSessionExpired
	}
	if s.registry.isRevoked(claims.Jti) {
		return "", ErrSessionRevoked
	}
	if claims.Sub == "" {
		return "", ErrSessionNotFound
	}
	return claims.Sub, nil
}

// Delete revokes a token (user logout): its jti is denylisted until the token's
// natural expiry, after which it is pruned. A no-op for an unverifiable token.
func (s *SessionStore) Delete(token string) {
	claims, err := s.verify(token)
	if err != nil || claims.Jti == "" {
		return
	}
	s.registry.revoke(claims.Jti, claims.Exp)
}

// jwtHeader is the fixed HS256 header; we always verify as HS256 and ignore the
// header's alg field, so there is no algorithm-confusion surface.
var jwtHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

func (s *SessionStore) sign(claims jwtClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := jwtHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// verify checks the HMAC (always HS256) and parses the claims. It does not check
// expiry or revocation — Validate does that.
func (s *SessionStore) verify(token string) (jwtClaims, error) {
	var zero jwtClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, errors.New("malformed token")
	}
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, expected) {
		return zero, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return zero, err
	}
	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return zero, err
	}
	return claims, nil
}

// LoadOrCreateSecret returns a persisted HMAC signing secret, generating and
// writing a new 32-byte random one (base64, 0600) if the file does not exist.
func LoadOrCreateSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		secret, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr != nil || len(secret) < 32 {
			return nil, fmt.Errorf("webcore: invalid signing secret in %s", path)
		}
		return secret, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("webcore: read signing secret: %w", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("webcore: generate signing secret: %w", err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(secret)), 0600); err != nil {
		return nil, fmt.Errorf("webcore: persist signing secret: %w", err)
	}
	return secret, nil
}

// revokeRegistry is a small persisted denylist of revoked token IDs (jti -> exp
// unix seconds). Expired entries are pruned.
type revokeRegistry struct {
	mu      sync.Mutex
	path    string // "" = in-memory only
	revoked map[string]int64
}

func newRevokeRegistry(path string) (*revokeRegistry, error) {
	r := &revokeRegistry{path: path, revoked: make(map[string]int64)}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("webcore: read revoke registry: %w", err)
	}
	if err := json.Unmarshal(data, &r.revoked); err != nil {
		return nil, fmt.Errorf("webcore: parse revoke registry: %w", err)
	}
	r.prune()
	return r, nil
}

func (r *revokeRegistry) revoke(jti string, exp int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = exp
	r.prune()
	r.save()
}

func (r *revokeRegistry) isRevoked(jti string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.revoked[jti]
	return ok
}

// prune drops entries whose token has already expired (caller holds the lock,
// except at construction where there is no concurrency).
func (r *revokeRegistry) prune() {
	now := time.Now().Unix()
	for jti, exp := range r.revoked {
		if exp < now {
			delete(r.revoked, jti)
		}
	}
}

// save writes the denylist atomically (caller holds the lock).
func (r *revokeRegistry) save() {
	if r.path == "" {
		return
	}
	data, err := json.Marshal(r.revoked)
	if err != nil {
		return
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, r.path)
}
