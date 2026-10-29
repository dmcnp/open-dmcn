package identity

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateLocalPart(t *testing.T) {
	tests := []struct {
		name    string
		local   string
		wantErr error // nil, ErrLocalPartFormat, or ErrLocalPartIsPublicKey
	}{
		// valid
		{"simple", "me1", nil},
		{"one-char", "m", nil},
		{"two-char", "me", nil},
		{"one-digit", "7", nil},
		{"alnum", "a1b", nil},
		{"dot", "john.doe", nil},
		{"multi-dash", "a-b-c-d", nil},
		{"mixed-separators", "x_y-z", nil},
		{"digits", "007agent", nil},
		{"max-len-nonhex", "z" + strings.Repeat("a", 63), nil}, // 64 chars, not all-hex
		{"trailing-digit-after-dot", "v1.2.3", nil},

		// format failures
		{"empty", "", ErrLocalPartFormat},
		{"too-long", strings.Repeat("a", 65), ErrLocalPartFormat},
		{"lone-separator", "-", ErrLocalPartFormat},
		{"leading-dash", "-abc", ErrLocalPartFormat},
		{"trailing-dash", "abc-", ErrLocalPartFormat},
		{"leading-dot", ".abc", ErrLocalPartFormat},
		{"trailing-underscore", "abc_", ErrLocalPartFormat},
		{"uppercase", "Alice", ErrLocalPartFormat},
		{"space", "a b", ErrLocalPartFormat},
		{"plus", "me+tag", ErrLocalPartFormat},
		{"at", "a@b", ErrLocalPartFormat},
		{"double-underscore", "a__b", ErrLocalPartFormat},
		{"double-dot", "a..b", ErrLocalPartFormat},
		{"underscore-dash", "a_-b", ErrLocalPartFormat},
		{"dot-underscore", "a._b", ErrLocalPartFormat},

		// public-key look-alikes
		{"hex-key-64", strings.Repeat("ab", 32), ErrLocalPartIsPublicKey},
		{"hex-fingerprint-40", strings.Repeat("de", 20), ErrLocalPartIsPublicKey},
		// all-hex but not a key/fingerprint length → allowed
		{"hex-42-ok", strings.Repeat("ab", 21), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLocalPart(tt.local)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateLocalPart(%q) = %v, want nil", tt.local, err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateLocalPart(%q) = %v, want %v", tt.local, err, tt.wantErr)
			}
		})
	}
}

func TestValidateChosenAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"valid", "alice@example.com", false},
		{"valid-dashes", "a-b-c@example.com", false},
		{"bad-local", "Alice@example.com", true},
		{"short-local", "me@example.me", false},
		{"pubkey-local", strings.Repeat("ab", 32) + "@example.com", true},
		{"no-domain", "alice@", true},
		{"no-at", "alice", true},
		{"empty-local", "@example.com", true},
		{"domain-with-at", "alice@ex@ample.com", true}, // second @ lands in domain
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChosenAddress(tt.address)
			if tt.wantErr && err == nil {
				t.Fatalf("ValidateChosenAddress(%q) = nil, want error", tt.address)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("ValidateChosenAddress(%q) = %v, want nil", tt.address, err)
			}
		})
	}
}
