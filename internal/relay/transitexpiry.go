package relay

import (
	"context"
	"time"
)

// ownQueueGrace is how much longer than transitMaxAge the queue addressed to this relay's own
// key is kept. That queue is a co-located bridge's outbound mail, and the bridge gives up on it
// at transitMaxAge itself so it can tell the sender, which the relay cannot: it holds only
// ciphertext and never learns who sent it. The grace keeps the relay's sweep from getting there
// first — including when a bridge starts long after its relay, as dmcnd's does once its domain
// is live — while a relay with no bridge running still drops that queue eventually.
const ownQueueGrace = 24 * time.Hour

// WithTransitMaxAge bounds how long undelivered mail may wait in the in-flight store. An envelope
// that nobody has collected after d is dropped; 0 (the default) keeps it until it is collected.
// Mail in the durable mailbox is not affected: it is the owner's to keep.
func WithTransitMaxAge(d time.Duration) Option {
	return func(o *relayOptions) {
		o.transitMaxAge = d
	}
}

// WithRelayX25519Pub tells the relay its own X25519 public key: the key a co-located bridge
// receives outbound mail on, whose queue the expiry sweep gives ownQueueGrace longer.
func WithRelayX25519Pub(pub [32]byte) Option {
	return func(o *relayOptions) {
		o.relayXPub = pub
	}
}

// startTransitExpiry runs the in-flight store's expiry sweep. Called from Start.
func (r *Relay) startTransitExpiry(ctx context.Context) {
	if r.transitMaxAge <= 0 {
		return
	}
	// A sweep is cheap, and an envelope outliving its lifetime by up to one tick is harmless.
	tick := min(max(r.transitMaxAge/100, time.Minute), time.Hour)
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.expireTransit(time.Now())
			}
		}
	}()
}

// expireTransit drops the in-flight envelopes that have waited longer than transitMaxAge, or
// longer than transitMaxAge + ownQueueGrace for the queue addressed to this relay's own key.
func (r *Relay) expireTransit(now time.Time) {
	cutoff := now.Add(-r.transitMaxAge)
	ownCutoff := cutoff.Add(-ownQueueGrace)
	n := r.store.Expire(func(addr string) time.Time {
		if r.relayXPubHex != "" && addr == r.relayXPubHex {
			return ownCutoff
		}
		return cutoff
	})
	if n > 0 {
		r.log.Infof("in-flight store: dropped %d envelope(s) nobody collected in time", n)
	}
}
