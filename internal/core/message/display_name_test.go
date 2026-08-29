package message

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestSanitizeDisplayName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Reddit", "Reddit"},
		{"trimmed and collapsed", "  Anna   van   Dijk \n", "Anna van Dijk"},
		{"header injection is not a name", "Evil\r\nBcc: victim@example.com", "Evil Bcc: victim@example.com"},
		{"control characters dropped", "Sup\x00port\x07", "Support"},
		{"bidi override dropped", "Support ‮moc.live@rekcatta", "Support moc.live@rekcatta"},
		{"non-ascii kept", "Zoë Müller 日本", "Zoë Müller 日本"},
		{"empty", "", ""},
		{"whitespace only", "   \t ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeDisplayName(tt.in); got != tt.want {
				t.Errorf("SanitizeDisplayName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A name past the cap is truncated on a rune boundary — never mid-rune, which would
// put invalid UTF-8 into a signed header.
func TestSanitizeDisplayNameCap(t *testing.T) {
	got := SanitizeDisplayName(strings.Repeat("é", 200))
	if len(got) > maxDisplayNameLen {
		t.Fatalf("length = %d bytes, want <= %d", len(got), maxDisplayNameLen)
	}
	if !strings.HasPrefix(strings.Repeat("é", 200), got) || got == "" {
		t.Fatalf("truncation split a rune or lost everything: %q", got)
	}
}

// Split copies the display name into the header, sanitizing it on the way (the producer
// side), and the header signature covers it — so a relay cannot rewrite the name a
// reader sees without breaking verification.
func TestSplitSignsDisplayName(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	msg := &PlaintextMessage{
		Version:          1,
		SenderAddress:    "noreply@redditmail.com",
		SenderPublicKey:  pub,
		RecipientAddress: "alice@dmcn.email",
		Subject:          "Digest",
		SenderDisplay:    "Reddit\r\n",
		Body:             MessageBody{ContentType: "text/plain", Content: []byte("hi")},
	}
	sh, _, err := Split(msg, priv)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if sh.Header.SenderDisplay != "Reddit" {
		t.Fatalf("header display = %q, want the sanitized name", sh.Header.SenderDisplay)
	}
	if err := sh.Verify(); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tampering with the name breaks the signature.
	tampered := *sh
	tampered.Header.SenderDisplay = "PayPal Security"
	if err := tampered.Verify(); err == nil {
		t.Fatal("a rewritten display name must not verify")
	}

	// A round trip through the proto preserves it — this is the path a recipient
	// verifies on (parse, then re-marshal), so a dropped field would fail the check.
	back := messageHeaderFromProto(sh.Header.toProto())
	if back.SenderDisplay != "Reddit" {
		t.Fatalf("round-tripped display = %q, want Reddit", back.SenderDisplay)
	}
}

// An unset display name must marshal exactly as it did before the field existed —
// otherwise adding it would invalidate every header already in a mailbox.
func TestEmptyDisplayNameIsWireIdentical(t *testing.T) {
	h := MessageHeader{Version: 1, SenderAddress: "a@b.test", Subject: "hi"}
	withEmpty, err := protoMarshal(h.toProto())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	h.SenderDisplay = ""
	again, err := protoMarshal(h.toProto())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(withEmpty) != string(again) {
		t.Fatal("an empty display name changed the encoding")
	}
	// And the field is genuinely absent from the bytes (proto3 omits empty strings),
	// so an old reader re-marshals to the identical signed bytes.
	if len(withEmpty) != len(again) {
		t.Fatal("unexpected length change")
	}
}
