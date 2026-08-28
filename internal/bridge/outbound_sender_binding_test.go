package bridge_test

import (
	"context"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// The outbound handler verifies the sender signature against the public key carried
// INSIDE the message (SignedMessage.Verify → Plaintext.SenderPublicKey;
// SignedHeader.Verify → Header.SenderPublicKey). That proves the message is
// self-consistent and nothing more: it does not prove the signing key is the one the
// claimed sender address actually owns.
//
// The relay's STORE gate does bind a key to an address — crypto.Verify against
// senderRec.Ed25519Public (relay.go) — but it binds the key to the STORE request's
// CLEARTEXT sender address. The bridge reads SenderAddress from the DECRYPTED header.
// Those are independent fields, so passing the relay gate as yourself says nothing
// about whose name is inside the envelope.
//
// These tests pin the property that closes the gap: the bridge must reject a message
// whose inner sender key is not the key its registry record publishes for that address.
// Both envelope shapes are covered, because they sign different bytes and verify in
// different places.
//
// If these fail, the failure is an impersonation path with full DMARC alignment: any
// holder of any address on a served domain can have the bridge deliver legacy mail as
// any other address on that domain, DKIM-signed by the bridge.

// impersonatingEnvelope builds a legacy whole-message envelope that claims to be from
// victimAddr while being signed by the attacker's key — self-consistent, because the
// attacker's public key is what travels in the message.
func impersonatingEnvelope(t *testing.T, attackerKP, bridgeKP *identity.IdentityKeyPair, victimAddr, recipient string) *message.EncryptedEnvelope {
	t.Helper()
	msg, err := message.NewPlaintextMessage(victimAddr, recipient, "Updated bank details", "Please remit to the account below.", attackerKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(attackerKP.Ed25519Private); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sm.Verify(); err != nil {
		t.Fatalf("precondition: the forged message must be self-consistent, got %v", err)
	}
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: attackerKP.DeviceID, X25519Pub: bridgeKP.X25519Public}})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return env
}

// impersonatingSplitEnvelope is the same forgery in the split format the web client
// sends, where only the header is signed.
func impersonatingSplitEnvelope(t *testing.T, attackerKP, bridgeKP *identity.IdentityKeyPair, victimAddr, recipient string) *message.EncryptedEnvelope {
	t.Helper()
	msg, err := message.NewPlaintextMessage(victimAddr, recipient, "Updated bank details", "Please remit to the account below.", attackerKP.Ed25519Public)
	if err != nil {
		t.Fatalf("compose: %v", err)
	}
	sh, content, err := message.Split(msg, attackerKP.Ed25519Private)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if err := sh.Verify(); err != nil {
		t.Fatalf("precondition: the forged header must be self-consistent, got %v", err)
	}
	env, err := message.EncryptSplit(sh, content,
		[]message.RecipientInfo{{DeviceID: attackerKP.DeviceID, X25519Pub: bridgeKP.X25519Public}},
		attackerKP.Ed25519Private)
	if err != nil {
		t.Fatalf("encrypt split: %v", err)
	}
	if !env.IsSplit() {
		t.Fatal("built a non-split envelope; this test would not cover what it claims to")
	}
	return env
}

// registryOwning answers lookups the way a real registry would: the address resolves
// to the key its OWNER published, which in the forgery tests is not the key that
// signed the message.
func registryOwning(kp *identity.IdentityKeyPair) bridge.LookupFunc {
	return func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		return recordFor(addr, kp), nil
	}
}

func assertNoImpersonation(t *testing.T, err error, deliverer *bridge.StubSMTPDeliverer, victimAddr string) {
	t.Helper()
	if len(deliverer.Messages) > 0 {
		got := deliverer.Messages[0]
		t.Fatalf("IMPERSONATION: bridge delivered mail forged as %s.\n"+
			"  delivered From: %s\n  To: %s\n  Subject: %q\n"+
			"The inner sender key was the attacker's, and the registry record for %s publishes a different key. "+
			"The bridge never compared them (internal/bridge/outbound.go: senderRec is fetched but its Ed25519Public is unused).",
			victimAddr, got.From, got.To, got.Subject, victimAddr)
	}
	if err == nil {
		t.Fatal("expected rejection of a message whose signing key is not the claimed sender's registered key, got nil error")
	}
}

// A message claiming to be from a victim on a served domain, signed with someone
// else's key, must not be relayed to the legacy world.
func TestOutboundRejectsSenderKeyNotMatchingRecord(t *testing.T) {
	bridgeKP, attackerKP, victimKP := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	const victim = "ceo@dmcn.localhost"

	env := impersonatingEnvelope(t, attackerKP, bridgeKP, victim, "cfo@partner.example")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, registryOwning(victimKP), deliverer, bridgeKP, nil, 0)

	_, err := h.HandleEnvelope(context.Background(), env)
	assertNoImpersonation(t, err, deliverer, victim)
}

// Same forgery in the split format, which is what the web client actually sends —
// here only the header is signed, and it is signed with the attacker's key.
func TestOutboundRejectsSenderKeyNotMatchingRecordSplit(t *testing.T) {
	bridgeKP, attackerKP, victimKP := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)
	const victim = "ceo@dmcn.localhost"

	env := impersonatingSplitEnvelope(t, attackerKP, bridgeKP, victim, "cfo@partner.example")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, registryOwning(victimKP), deliverer, bridgeKP, nil, 0)

	_, err := h.HandleEnvelope(context.Background(), env)
	assertNoImpersonation(t, err, deliverer, victim)
}

// Control: the same handler, same registry, when the signing key IS the one the
// record publishes. This must deliver — otherwise the two tests above would pass
// for the wrong reason (a handler that rejects everything proves nothing).
func TestOutboundDeliversWhenSenderKeyMatchesRecord(t *testing.T) {
	bridgeKP, senderKP := mustKeyPair(t), mustKeyPair(t)
	const sender = "alice@dmcn.localhost"

	env := sealedToBridge(t, senderKP, bridgeKP, sender, "cfo@partner.example", "hi")
	deliverer := &bridge.StubSMTPDeliverer{}
	h := newOutboundAuthz(t, registryOwning(senderKP), deliverer, bridgeKP, nil, 0)

	if _, err := h.HandleEnvelope(context.Background(), env); err != nil {
		t.Fatalf("a correctly signed message must still deliver, got %v", err)
	}
	if len(deliverer.Messages) != 1 {
		t.Fatalf("expected one delivery, got %d", len(deliverer.Messages))
	}
}
