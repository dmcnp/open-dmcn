// Package crypto provides thin wrappers around Go standard library and
// golang.org/x/crypto primitives for the DMCN protocol.
//
// No cryptographic algorithm is implemented from scratch. All functions
// return explicit errors and never panic on invalid input.
//
// See SPEC.md §1 and §3.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// randReader is the entropy source used for all random operations.
// It defaults to crypto/rand.Reader but can be overridden in tests.
var randReader io.Reader = rand.Reader

var (
	// ErrInvalidKeySize is returned when a key has an incorrect length.
	ErrInvalidKeySize = errors.New("crypto: invalid key size")
	// ErrInvalidNonceSize is returned when a nonce has an incorrect length.
	ErrInvalidNonceSize = errors.New("crypto: invalid nonce size")
	// ErrDecryptionFailed is returned when authenticated decryption fails.
	ErrDecryptionFailed = errors.New("crypto: decryption failed")
	// ErrInvalidSignature is returned when an Ed25519 signature is invalid.
	ErrInvalidSignature = errors.New("crypto: invalid signature")
)

const (
	// Ed25519PublicKeySize is the size of an Ed25519 public key in bytes.
	Ed25519PublicKeySize = ed25519.PublicKeySize // 32
	// Ed25519PrivateKeySize is the size of an Ed25519 private key in bytes.
	Ed25519PrivateKeySize = ed25519.PrivateKeySize // 64
	// Ed25519SignatureSize is the size of an Ed25519 signature in bytes.
	Ed25519SignatureSize = ed25519.SignatureSize // 64

	// X25519KeySize is the size of an X25519 public or private key in bytes.
	X25519KeySize = 32

	// AES256KeySize is the required key size for AES-256 in bytes.
	AES256KeySize = 32
	// AESGCMNonceSize is the standard nonce size for AES-GCM (96 bits).
	AESGCMNonceSize = 12
	// AESGCMTagSize is the authentication tag size for AES-GCM (128 bits).
	AESGCMTagSize = 16

	// SHA256Size is the size of a SHA-256 hash in bytes.
	SHA256Size = sha256.Size // 32
)

// GenerateEd25519KeyPair generates a new Ed25519 signing key pair using
// crypto/rand as the entropy source.
//
// See SPEC.md §1.
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: ed25519 key generation: %w", err)
	}
	return pub, priv, nil
}

// Sign produces an Ed25519 signature over the given message using the
// provided private key.
//
// See SPEC.md §1 (identity self-signature) and §3 (message sender signature).
func Sign(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(privateKey) != Ed25519PrivateKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, Ed25519PrivateKeySize, len(privateKey))
	}
	sig := ed25519.Sign(privateKey, message)
	return sig, nil
}

// Verify checks an Ed25519 signature over the given message using the
// provided public key. Returns ErrInvalidSignature if the signature is
// not valid.
//
// See SPEC.md §1 and §3.
func Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if len(publicKey) != Ed25519PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, Ed25519PublicKeySize, len(publicKey))
	}
	if len(signature) != Ed25519SignatureSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, Ed25519SignatureSize, len(signature))
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateX25519KeyPair generates a new X25519 key exchange key pair.
// The private key is 32 random bytes; the public key is derived by
// scalar multiplication with the Curve25519 base point.
//
// See SPEC.md §1.
func GenerateX25519KeyPair() (publicKey, privateKey [X25519KeySize]byte, err error) {
	if _, err := io.ReadFull(randReader, privateKey[:]); err != nil {
		return publicKey, privateKey, fmt.Errorf("crypto: x25519 key generation: %w", err)
	}
	pub, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return publicKey, privateKey, fmt.Errorf("crypto: x25519 base point multiplication: %w", err)
	}
	copy(publicKey[:], pub)
	return publicKey, privateKey, nil
}

// X25519SharedSecret performs an X25519 Diffie-Hellman key exchange,
// computing a shared secret from a private key and a peer's public key.
//
// See SPEC.md §3 (KEM pattern — CEK wrapping).
func X25519SharedSecret(privateKey, peerPublicKey [X25519KeySize]byte) ([X25519KeySize]byte, error) {
	var shared [X25519KeySize]byte
	result, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return shared, fmt.Errorf("crypto: x25519 key exchange: %w", err)
	}
	copy(shared[:], result)
	return shared, nil
}

// DeriveKey derives a symmetric key from input keying material using
// HKDF-SHA256 (RFC 5869).
//
// Parameters:
//   - secret: the input keying material (e.g. X25519 shared secret)
//   - salt: optional salt value (can be nil)
//   - info: context and application-specific information
//   - length: desired output key length in bytes
//
// See SPEC.md §3 (KEM pattern — KWK derivation).
func DeriveKey(secret, salt, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, errors.New("crypto: derive key: length must be positive")
	}
	reader := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("crypto: hkdf derive: %w", err)
	}
	return key, nil
}

// AESGCMEncrypt encrypts plaintext using AES-256-GCM with a randomly
// generated 96-bit nonce. Returns the nonce, ciphertext (without tag),
// and authentication tag separately.
//
// The key must be exactly 32 bytes (AES-256).
//
// See SPEC.md §3 (payload encryption and CEK wrapping).
func AESGCMEncrypt(key, plaintext []byte) (nonce, ciphertext, tag []byte, err error) {
	if len(key) != AES256KeySize {
		return nil, nil, nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, AES256KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: gcm mode: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("crypto: nonce generation: %w", err)
	}

	// Seal appends ciphertext+tag to dst
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Split ciphertext and tag
	tagOffset := len(sealed) - AESGCMTagSize
	ciphertext = sealed[:tagOffset]
	tag = sealed[tagOffset:]

	return nonce, ciphertext, tag, nil
}

// AESGCMDecrypt decrypts ciphertext using AES-256-GCM with the provided
// nonce and authentication tag. Returns ErrDecryptionFailed if the tag
// verification fails (indicating tampered data).
//
// See SPEC.md §3 (payload decryption and CEK unwrapping).
func AESGCMDecrypt(key, nonce, ciphertext, tag []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, AES256KeySize, len(key))
	}
	if len(nonce) != AESGCMNonceSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidNonceSize, AESGCMNonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: gcm mode: %w", err)
	}

	// Rejoin ciphertext and tag for Open
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// SHA256Hash computes the SHA-256 digest of the input data.
//
// See SPEC.md §1 (fingerprint computation) and §3 (attachment content hash).
func SHA256Hash(data []byte) [SHA256Size]byte {
	return sha256.Sum256(data)
}

// RandomBytes generates n cryptographically secure random bytes using
// crypto/rand.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("crypto: random bytes: length must be non-negative")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return nil, fmt.Errorf("crypto: random bytes: %w", err)
	}
	return b, nil
}

// RandomUUID generates a random 16-byte UUID (version 4).
func RandomUUID() ([16]byte, error) {
	var uuid [16]byte
	if _, err := io.ReadFull(randReader, uuid[:]); err != nil {
		return uuid, fmt.Errorf("crypto: uuid generation: %w", err)
	}
	// Set version 4 and variant bits per RFC 4122
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return uuid, nil
}
