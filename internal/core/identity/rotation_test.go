package identity

import (
	"bytes"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
)

const rotAddr = "alice@dmcn.email"

// rotateTo builds the record that replaces `prev`, carrying a fully signed transition to
// `next`. It mirrors what the browser ceremony does: mint the entry, have the retiring key
// consent, have the incoming key accept, then self-sign the whole record with the new key.
func rotateTo(t *testing.T, prev *IdentityKeyPair, prevRec *IdentityRecord, next *IdentityKeyPair, at time.Time) *IdentityRecord {
	t.Helper()
	rec, err := NewIdentityRecord(prevRec.Address, next)
	if err != nil {
		t.Fatalf("NewIdentityRecord: %v", err)
	}
	rec.Revision = prevRec.Revision + 1

	e, err := NewRotationEntry(prevRec, next.Ed25519Public, next.X25519Public, rec.Revision, at)
	if err != nil {
		t.Fatalf("NewRotationEntry: %v", err)
	}
	if err := e.SignConsent(prev); err != nil {
		t.Fatalf("SignConsent: %v", err)
	}
	if err := e.SignAcceptance(next); err != nil {
		t.Fatalf("SignAcceptance: %v", err)
	}
	rec.RotationChain = AppendRotation(prevRec, e)
	if err := rec.Sign(next); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return rec
}

func genesisRecord(t *testing.T, kp *IdentityKeyPair) *IdentityRecord {
	t.Helper()
	rec, err := NewIdentityRecord(rotAddr, kp)
	if err != nil {
		t.Fatalf("NewIdentityRecord: %v", err)
	}
	if err := rec.Sign(kp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return rec
}

// TestUnrotatedRecordEncodesUnchanged is the precondition for adding a signed core field at
// all: a record that has never rotated must marshal to the exact bytes it did before
// rotation_chain and recovery_ed25519_public_key existed. If this moves, every client whose
// bundle predates the schema starts rejecting every record on the network.
func TestUnrotatedRecordEncodesUnchanged(t *testing.T) {
	rec := genesisRecord(t, mustKP(t))
	pb := rec.ToProto()
	if len(pb.RotationChain) != 0 {
		t.Fatalf("unrotated record encodes %d chain entries, want 0", len(pb.RotationChain))
	}
	if len(pb.RecoveryEd25519PublicKey) != 0 {
		t.Fatalf("unrotated record encodes a recovery key, want none")
	}
	// Field presence is what costs bytes: assert the wire form is identical to the same
	// record marshaled with both fields explicitly cleared.
	withFields, err := proto.MarshalOptions{Deterministic: true}.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	pb.RotationChain = nil
	pb.RecoveryEd25519PublicKey = nil
	without, err := proto.MarshalOptions{Deterministic: true}.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(withFields, without) {
		t.Fatalf("empty rotation fields contribute bytes: %d vs %d", len(withFields), len(without))
	}
}

func TestRotationChainVerifies(t *testing.T) {
	k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
	now := time.Now().Truncate(time.Second)

	r0 := genesisRecord(t, k0)
	if err := VerifyRotationChain(r0); err != nil {
		t.Fatalf("empty chain should verify: %v", err)
	}

	r1 := rotateTo(t, k0, r0, k1, now)
	if err := VerifyRotationChain(r1); err != nil {
		t.Fatalf("one-entry chain: %v", err)
	}
	if err := r1.Verify(); err != nil {
		t.Fatalf("record self-signature over the chain: %v", err)
	}
	if ChainTruncated(r1.RotationChain) {
		t.Fatal("a chain starting at genesis should not read as truncated")
	}

	r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
	if err := VerifyRotationChain(r2); err != nil {
		t.Fatalf("two-entry chain: %v", err)
	}
	if got := len(r2.RotationChain); got != 2 {
		t.Fatalf("chain length %d, want 2", got)
	}
	if at, ok := RotatedFrom(r2, k0.Ed25519Public); !ok || !at.Equal(now) {
		t.Fatalf("RotatedFrom(k0) = %v, %v; want the genesis rotation time", at, ok)
	}
	if _, ok := RotatedFrom(r2, k2.Ed25519Public); ok {
		t.Fatal("the CURRENT key should not read as rotated away from")
	}
}

// TestIdentityRecordRejectsShortRecoveryKey: the self-signature covers whatever bytes are in the
// field, so a truncated recovery key rides along on a record that verifies perfectly. The owner
// believes recovery is enrolled and finds out otherwise on the one day it matters — the rotation
// arm compares it against a 32-byte authorizing key, so a shorter one can never match. Refusing
// it where the record is parsed is the only point at which anyone still has a chance to fix it.
func TestIdentityRecordRejectsShortRecoveryKey(t *testing.T) {
	k0 := mustKP(t)
	rec := genesisRecord(t, k0)
	pb := rec.ToProto()
	pb.RecoveryEd25519PublicKey = mustKP(t).Ed25519Public[:16]

	if _, err := IdentityRecordFromProto(pb); err == nil {
		t.Fatal("a 16-byte recovery key was accepted")
	}

	// And none at all is still fine: the field is optional, and most records carry no recovery key.
	pb.RecoveryEd25519PublicKey = nil
	if _, err := IdentityRecordFromProto(pb); err != nil {
		t.Fatalf("a record with no recovery key was refused: %v", err)
	}
}

// TestRotationChainSurvivesProtoRoundTrip guards the wire path: a chain silently dropped on
// decode would make every rotated record look un-rotated, which reads as a substitution.
func TestRotationChainSurvivesProtoRoundTrip(t *testing.T) {
	k0, k1 := mustKP(t), mustKP(t)
	r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, time.Now().Truncate(time.Second))
	r1.RecoveryEd25519Public = mustKP(t).Ed25519Public

	back, err := IdentityRecordFromProto(r1.ToProto())
	if err != nil {
		t.Fatalf("IdentityRecordFromProto: %v", err)
	}
	if len(back.RotationChain) != 1 {
		t.Fatalf("chain length %d after round trip, want 1", len(back.RotationChain))
	}
	if !bytes.Equal(back.RecoveryEd25519Public, r1.RecoveryEd25519Public) {
		t.Fatal("recovery key lost in round trip")
	}
	if err := VerifyRotationChain(back); err != nil {
		t.Fatalf("round-tripped chain: %v", err)
	}
}

// TestRotationChainIsSelfSigned: the chain rides inside the owner self-signature, so editing
// it invalidates the record. This is what stops a relay stripping or rewriting history.
func TestRotationChainIsSelfSigned(t *testing.T) {
	k0, k1 := mustKP(t), mustKP(t)
	r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, time.Now())

	stripped := *r1
	stripped.RotationChain = nil
	if err := stripped.Verify(); err == nil {
		t.Fatal("dropping the chain should break the record self-signature")
	}
}

func TestRotationChainRejections(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	tests := []struct {
		name string
		// build returns a record whose chain must be refused.
		build func(t *testing.T) *IdentityRecord
	}{
		{"tampered consent signature", func(t *testing.T) *IdentityRecord {
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].Signature[0] ^= 0xff
			return r
		}},
		{"tampered acceptance signature", func(t *testing.T) *IdentityRecord {
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].NextSignature[0] ^= 0xff
			return r
		}},
		{"acceptance replayed as consent", func(t *testing.T) *IdentityRecord {
			// Distinct signing contexts exist so a key that merely RECEIVED an address
			// cannot appear to have handed it on.
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].Signature = r.RotationChain[0].NextSignature
			return r
		}},
		{"consent by a key that is not the authorizing one", func(t *testing.T) *IdentityRecord {
			k0, k1, evil := mustKP(t), mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].AuthorizingEd25519Public = evil.Ed25519Public
			return r
		}},
		{"terminal entry hands over to a different key", func(t *testing.T) *IdentityRecord {
			k0, k1, other := mustKP(t), mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.Ed25519Public = other.Ed25519Public
			return r
		}},
		{"terminal revision disagrees with the record", func(t *testing.T) *IdentityRecord {
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.Revision += 7
			return r
		}},
		{"entry belongs to another address", func(t *testing.T) *IdentityRecord {
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].Address = "mallory@dmcn.email"
			return r
		}},
		{"broken key linkage between entries", func(t *testing.T) *IdentityRecord {
			k0, k1, k2, stray := mustKP(t), mustKP(t), mustKP(t), mustKP(t)
			r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
			r2.RotationChain[1].RetiredEd25519Public = stray.Ed25519Public
			return r2
		}},
		{"broken prev_signature_hash", func(t *testing.T) *IdentityRecord {
			k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
			r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
			r2.RotationChain[1].PrevSignatureHash[0] ^= 0xff
			return r2
		}},
		{"time does not advance", func(t *testing.T) *IdentityRecord {
			k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
			r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
			r2.RotationChain[1].RotatedAt = r2.RotationChain[0].RotatedAt
			return r2
		}},
		{"revision does not advance", func(t *testing.T) *IdentityRecord {
			k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
			r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
			r2.RotationChain[1].NextRevision = r2.RotationChain[0].NextRevision
			return r2
		}},
		{"transition to the key already held", func(t *testing.T) *IdentityRecord {
			k0, k1 := mustKP(t), mustKP(t)
			r := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
			r.RotationChain[0].RetiredEd25519Public = r.RotationChain[0].NextEd25519Public
			return r
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.build(t)
			if err := VerifyRotationChain(rec); err == nil {
				t.Fatal("chain verified, want refusal")
			}
		})
	}
}

// TestRotationChainCapAndTruncation: the on-record window is bounded, and going over it is
// detectable rather than silent — which is what points a reader at the history record and
// what keeps a key rotating in a loop from quietly curating its own lineage.
func TestRotationChainCapAndTruncation(t *testing.T) {
	kp := mustKP(t)
	rec := genesisRecord(t, kp)
	at := time.Now().Truncate(time.Second)

	for i := 0; i < MaxRotationChain+3; i++ {
		next := mustKP(t)
		at = at.Add(time.Hour)
		rec = rotateTo(t, kp, rec, next, at)
		kp = next
	}

	if got := len(rec.RotationChain); got != MaxRotationChain {
		t.Fatalf("chain length %d, want it capped at %d", got, MaxRotationChain)
	}
	if err := VerifyRotationChain(rec); err != nil {
		t.Fatalf("a truncated chain should still verify: %v", err)
	}
	if !ChainTruncated(rec.RotationChain) {
		t.Fatal("a chain that dropped older links should read as truncated")
	}

	over := *rec
	over.RotationChain = append(append([]RotationEntry{}, rec.RotationChain...), rec.RotationChain[0])
	if err := VerifyRotationChain(&over); err == nil {
		t.Fatal("a chain longer than the cap should be refused")
	}
}

// TestRecordAcceptsSubject: an operator grant minted before a rotation survives it, so a
// drain, a billing retry or a replica repair can still push it; one minted afterwards against
// a dead key is refused.
func TestRecordAcceptsSubject(t *testing.T) {
	k0, k1 := mustKP(t), mustKP(t)
	rotatedAt := time.Now().Truncate(time.Second)
	rec := rotateTo(t, k0, genesisRecord(t, k0), k1, rotatedAt)

	if !RecordAcceptsSubject(rec, k1.Ed25519Public, rotatedAt.Add(time.Hour)) {
		t.Fatal("the current key should be accepted")
	}
	if !RecordAcceptsSubject(rec, k0.Ed25519Public, rotatedAt.Add(-time.Hour)) {
		t.Fatal("a retired key should be accepted for a grant issued before the rotation")
	}
	if RecordAcceptsSubject(rec, k0.Ed25519Public, rotatedAt.Add(time.Hour)) {
		t.Fatal("a retired key must be refused for a grant issued after the rotation")
	}
	if RecordAcceptsSubject(rec, mustKP(t).Ed25519Public, rotatedAt) {
		t.Fatal("an unrelated key must be refused")
	}
}

// TestRecoverySignedRotation: the recovery key may consent in place of the key being retired,
// which is the whole point of holding one — losing the active key stops being terminal. The
// entry names which key signed so history stays verifiable without the prior record.
func TestRecoverySignedRotation(t *testing.T) {
	k0, recovery, k1 := mustKP(t), mustKP(t), mustKP(t)

	r0 := genesisRecord(t, k0)
	r0.RecoveryEd25519Public = recovery.Ed25519Public
	if err := r0.Sign(k0); err != nil {
		t.Fatal(err)
	}

	rec, err := NewIdentityRecord(rotAddr, k1)
	if err != nil {
		t.Fatal(err)
	}
	rec.Revision = r0.Revision + 1
	e, err := NewRotationEntry(r0, k1.Ed25519Public, k1.X25519Public, rec.Revision, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// A recovery-signed rotation declares its authorizing key before anything signs over it.
	e.AuthorizingEd25519Public = recovery.Ed25519Public
	if err := e.SignConsent(recovery); err != nil {
		t.Fatal(err)
	}
	if err := e.SignAcceptance(k1); err != nil {
		t.Fatal(err)
	}
	rec.RotationChain = AppendRotation(r0, e)
	if err := rec.Sign(k1); err != nil {
		t.Fatal(err)
	}

	if err := VerifyRotationChain(rec); err != nil {
		t.Fatalf("recovery-signed chain: %v", err)
	}
	if !rec.RotationChain[0].RecoverySigned() {
		t.Fatal("entry should report that a recovery key authorized it")
	}
	if !bytes.Equal(rec.RotationChain[0].AuthorizingEd25519Public, recovery.Ed25519Public) {
		t.Fatal("entry should name the recovery key as the authorizing one")
	}
}

// TestNewRotationEntryChainsToPredecessor: a new entry must reference the previous entry's
// signature, or truncation and re-ordering stop being detectable.
func TestNewRotationEntryChainsToPredecessor(t *testing.T) {
	k0, k1, k2 := mustKP(t), mustKP(t), mustKP(t)
	now := time.Now().Truncate(time.Second)

	r1 := rotateTo(t, k0, genesisRecord(t, k0), k1, now)
	if len(r1.RotationChain[0].PrevSignatureHash) != 0 {
		t.Fatal("the first rotation should carry no predecessor hash")
	}

	r2 := rotateTo(t, k1, r1, k2, now.Add(time.Hour))
	want := crypto.SHA256Hash(r1.RotationChain[0].Signature)
	if !bytes.Equal(r2.RotationChain[1].PrevSignatureHash, want[:]) {
		t.Fatal("the second rotation should hash the first entry's signature")
	}
}

func TestNewRotationEntryRefusesStaleRevision(t *testing.T) {
	k0 := mustKP(t)
	r0 := genesisRecord(t, k0)
	if _, err := NewRotationEntry(r0, mustKP(t).Ed25519Public, [32]byte{}, r0.Revision, time.Now()); err == nil {
		t.Fatal("a rotation that does not advance the revision should be refused")
	}
}
