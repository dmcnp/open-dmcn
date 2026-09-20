package identity

import (
	"testing"
	"time"
)

// historyFor builds a complete history by rotating an account `n` times, which is the only way to
// get entries that genuinely chain: each signs over the one before it.
func historyFor(t *testing.T, n int) (*AddressHistoryRecord, []*IdentityKeyPair) {
	t.Helper()
	kp := mustKP(t)
	keys := []*IdentityKeyPair{kp}
	rec := genesisRecord(t, kp)
	at := time.Now().Truncate(time.Second)

	h, err := NewAddressHistoryRecord("dmcn.email", rotAddr)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		next := mustKP(t)
		at = at.Add(time.Hour)
		rec = rotateTo(t, kp, rec, next, at)
		h.Chain = append(h.Chain, rec.RotationChain[len(rec.RotationChain)-1])
		kp = next
		keys = append(keys, next)
	}
	return h, keys
}

func TestHistoryVerifies(t *testing.T) {
	h, _ := historyFor(t, 3)
	if err := h.Verify(); err != nil {
		t.Fatalf("a genuine history should verify: %v", err)
	}
	if got := len(h.Chain); got != 3 {
		t.Fatalf("chain length %d, want 3", got)
	}
}

// TestHistoryMustBeComplete: this record is where a reader comes when the capped chain on the
// identity record already fell short, so a truncated one here would leave them with nowhere
// further to look while appearing to be the whole answer.
func TestHistoryMustBeComplete(t *testing.T) {
	h, _ := historyFor(t, 3)
	h.Chain = h.Chain[1:] // drop the genesis transition
	if err := h.Verify(); err == nil {
		t.Fatal("a history beginning part-way through was accepted as complete")
	}
}

func TestHistoryRejections(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(h *AddressHistoryRecord)
	}{
		{"an entry belonging to another address", func(h *AddressHistoryRecord) {
			h.Chain[1].Address = "mallory@dmcn.email"
		}},
		{"a tampered signature", func(h *AddressHistoryRecord) {
			h.Chain[1].Signature[0] ^= 0xff
		}},
		{"a broken link between entries", func(h *AddressHistoryRecord) {
			h.Chain[2].PrevSignatureHash[0] ^= 0xff
		}},
		{"a domain that is not the address's", func(h *AddressHistoryRecord) {
			h.Domain = "elsewhere.example"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := historyFor(t, 3)
			tc.break_(h)
			if err := h.Verify(); err == nil {
				t.Fatal("history verified, want refusal")
			}
		})
	}
}

// TestHistoryOnlyGrows is the property that makes this record worth reading at all. If a later
// publish could rewrite what an earlier one recorded, the history would attest only to whatever
// its holder last chose to say.
func TestHistoryOnlyGrows(t *testing.T) {
	full, _ := historyFor(t, 4)

	prefix := &AddressHistoryRecord{Version: 1, Domain: full.Domain, Address: full.Address, Chain: full.Chain[:2]}
	if !full.Extends(prefix) {
		t.Fatal("a longer history should extend its own prefix")
	}
	if prefix.Extends(full) {
		t.Fatal("a shorter history must not extend a longer one")
	}
	if full.Extends(full) {
		t.Fatal("an unchanged history is not an extension — re-publishing is a no-op, not growth")
	}

	// A history of the same length that disagrees about the past is the case the rule exists for.
	rewritten := &AddressHistoryRecord{Version: 1, Domain: full.Domain, Address: full.Address}
	rewritten.Chain = append(rewritten.Chain, full.Chain...)
	rewritten.Chain[0].Signature = append([]byte(nil), full.Chain[0].Signature...)
	rewritten.Chain[0].Signature[0] ^= 0xff
	rewritten.Chain = append(rewritten.Chain, full.Chain[len(full.Chain)-1])
	if rewritten.Extends(full) {
		t.Fatal("a history that rewrote an earlier entry was accepted as an extension")
	}
}

// TestHistoryAnswersTheReadersQuestion: a pin that fell outside the capped on-record window is
// exactly what this record is consulted about.
func TestHistoryAnswersTheReadersQuestion(t *testing.T) {
	h, keys := historyFor(t, 3)

	at, ok := h.RotatedFrom(keys[0].Ed25519Public)
	if !ok {
		t.Fatal("the original key should be found in the history")
	}
	if !at.Equal(h.Chain[0].RotatedAt) {
		t.Fatalf("handover time %v, want %v", at, h.Chain[0].RotatedAt)
	}
	// The CURRENT key was never rotated away from, so it is not part of the past.
	if _, ok := h.RotatedFrom(keys[len(keys)-1].Ed25519Public); ok {
		t.Fatal("the current key should not read as one the address used to hold")
	}
	if _, ok := h.RotatedFrom(mustKP(t).Ed25519Public); ok {
		t.Fatal("a stranger's key must not be found in this address's history")
	}
}

func TestHistorySurvivesProtoRoundTrip(t *testing.T) {
	h, _ := historyFor(t, 3)
	back, err := AddressHistoryRecordFromProto(h.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Chain) != len(h.Chain) {
		t.Fatalf("chain length %d after round trip, want %d", len(back.Chain), len(h.Chain))
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("round-tripped history: %v", err)
	}
}
