package bridge

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"testing"
	"time"
)

// TestEmitClassificationGolden prints a deterministic golden vector (fixed key +
// fields) for cross-checking the web client's signable-bytes reproduction against
// Go's. Skipped unless DMCN_EMIT_GOLDEN is set, so it never runs in CI.
func TestEmitClassificationGolden(t *testing.T) {
	if os.Getenv("DMCN_EMIT_GOLDEN") == "" {
		t.Skip("set DMCN_EMIT_GOLDEN=1 to emit the golden vector")
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = 7
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	rec := &BridgeClassificationRecord{
		BridgeAddress:   tBridgePeerID,
		BridgePublicKey: pub,
		SMTPFrom:        "alice@gmail.com",
		SMTPSenderIP:    "203.0.113.7",
		SPFResult:       SPFPass,
		DKIMResult:      DKIMPass,
		DMARCResult:     DMARCPass,
		TrustTier:       TrustTierVerifiedLegacy,
		ClassifiedAt:    time.Unix(1700000000, 0).UTC(),
	}
	if err := rec.Sign(priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	full, _ := rec.Marshal()
	sb, _ := rec.signableBytes()
	enc := base64.StdEncoding.EncodeToString
	t.Logf("PUB %s", enc(pub))
	t.Logf("FULL %s", enc(full))
	t.Logf("SIGNABLE %s", enc(sb))
	t.Logf("SIG %s", enc(rec.BridgeSignature[:]))
}
