package relay

import (
	"fmt"
	"testing"
	"time"
)

// The sweep drops in-flight mail nobody collected in time. The queue addressed to the relay's own
// key — a co-located bridge's outbound mail — gets a day longer, so the bridge, which gives up at
// the lifetime itself and tells the sender, always gets there first; with no bridge to collect
// it, that queue still goes.
func TestExpireTransitGivesOwnQueueGrace(t *testing.T) {
	h := newTestHost(t)
	defer h.Close()
	own := [32]byte{0xb1}
	ownHex := fmt.Sprintf("%x", own[:])
	r := New(h, nil, WithTransitMaxAge(time.Hour), WithRelayX25519Pub(own))

	queued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	r.store.now = func() time.Time { return queued }
	r.store.Store("aa", testEnvelope(t), [32]byte{1})
	r.store.Store(ownHex, testEnvelope(t), [32]byte{2})

	r.expireTransit(queued.Add(2 * time.Hour))
	if q := r.store.Queued("aa"); len(q) != 0 {
		t.Fatal("uncollected mail outlived the transit lifetime")
	}
	if q := r.store.Queued(ownHex); len(q) != 1 {
		t.Fatal("the bridge's queue was swept before the bridge could give up on it")
	}

	r.expireTransit(queued.Add(time.Hour + ownQueueGrace + time.Minute))
	if q := r.store.Queued(ownHex); len(q) != 0 {
		t.Fatal("the own-key queue outlived its lifetime and grace")
	}
}
