package bridge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

func newRetryBridge() *Bridge {
	return &Bridge{retries: make(map[[32]byte]retryState), inFlight: make(map[[32]byte]bool), routed: make(map[[32]byte]routedMessage)}
}

// Outbound retries start a minute apart, double, and settle at every six hours; an envelope is
// not tried again before its time.
func TestOutboundRetrySchedule(t *testing.T) {
	b := newRetryBridge()
	hash := [32]byte{1}

	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute,
		32 * time.Minute, 64 * time.Minute, 128 * time.Minute, 256 * time.Minute, 6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		before := time.Now()
		next := b.deferRetry(hash)
		if got := next.Sub(before); got < w || got > w+time.Second {
			t.Fatalf("retry %d waits %s, want %s", i+1, got, w)
		}
	}
	if b.claim(hash) {
		t.Fatal("an envelope was claimed before its next attempt was due")
	}
	for i := 0; i < 100; i++ {
		b.deferRetry(hash)
	}
	if got := time.Until(b.retries[hash].next); got > maxRetry {
		t.Fatalf("after many retries the wait is %s, past the %s cap", got, maxRetry)
	}
}

// A due envelope is claimed once: while an attempt at it runs, no second worker takes it.
func TestOutboundClaimIsExclusive(t *testing.T) {
	b := newRetryBridge()
	hash := [32]byte{2}
	if !b.claim(hash) {
		t.Fatal("a new envelope could not be claimed")
	}
	if b.claim(hash) {
		t.Fatal("an envelope under way was claimed twice")
	}
	b.release(hash)
	if !b.claim(hash) {
		t.Fatal("a released envelope could not be claimed again")
	}
}

// A server that accepts the message and then drops the connection before answering QUIT has
// delivered it. Reporting that as a failure would send it again.
func TestSMTPSenderQuitFailureAfterDataIsDelivered(t *testing.T) {
	ln := startDroppingServer(t)
	s := senderTo(ln, SMTPSenderConfig{})
	if err := s.Deliver(context.Background(), "alice@bridge.test", "bob@example.com", plainMsg("Hi", "hello"), Audience{}); err != nil {
		t.Fatalf("a message the server accepted was reported as failed: %v", err)
	}
}

// A queued envelope the bridge cannot even load is retried on the schedule like anything else,
// and dropped once its lifetime is up, rather than being tried every poll forever.
func TestUnloadableEnvelopeHasALifetime(t *testing.T) {
	b := newRetryBridge()
	b.maxAge = time.Hour
	b.log = testLogr()
	b.outbound = NewOutboundHandler(OutboundConfig{Log: b.log})
	removed := map[[32]byte]bool{}
	item := func(hash byte, queued time.Time) outboundItem {
		return outboundItem{
			hash:     [32]byte{hash},
			queuedAt: queued,
			load:     func() (*message.EncryptedEnvelope, error) { return nil, errors.New("body missing") },
			remove:   func() error { removed[[32]byte{hash}] = true; return nil },
		}
	}

	if _, ok := b.open(item(1, time.Now())); ok || removed[[32]byte{1}] {
		t.Fatal("an envelope inside its lifetime was opened or dropped")
	}
	if b.claim([32]byte{1}) {
		t.Fatal("an unloadable envelope is due again at once instead of on the schedule")
	}

	if _, ok := b.open(item(2, time.Now().Add(-2*time.Hour))); ok || !removed[[32]byte{2}] {
		t.Fatal("an unloadable envelope outlived its lifetime")
	}
}

// newPoolBridge is a bridge whose domain workers hand each job to handle instead of delivering it.
func newPoolBridge(t *testing.T, handle func(outboundJob)) *Bridge {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	b := newRetryBridge()
	b.ctx, b.cancel = ctx, cancel
	b.pool = newWorkerPool()
	b.wake = make(chan struct{}, 1)
	b.handleJob = handle
	t.Cleanup(func() { cancel(); b.work.Wait() })
	return b
}

func job(n byte) outboundJob { return outboundJob{item: outboundItem{hash: [32]byte{n}}} }

// waitIdle waits until every domain worker is back in the pool.
func waitIdle(t *testing.T, b *Bridge) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.pool.mu.Lock()
		idle, active := len(b.pool.idle), len(b.pool.active)
		b.pool.mu.Unlock()
		if idle == outboundWorkers && active == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("workers did not return to the pool: %d idle, %d active", idle, active)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A domain's worker drains its queue in order, one message after another, then goes back to the
// pool.
func TestDomainWorkerDrainsItsQueueThenReturnsToThePool(t *testing.T) {
	var mu sync.Mutex
	var order []byte
	b := newPoolBridge(t, func(j outboundJob) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, j.item.hash[0])
	})
	for n := byte(1); n <= 5; n++ {
		if !b.enqueue("gmail.com", job(n)) {
			t.Fatalf("job %d was not queued", n)
		}
	}
	waitIdle(t, b)
	mu.Lock()
	defer mu.Unlock()
	if string(order) != string([]byte{1, 2, 3, 4, 5}) {
		t.Fatalf("delivered in order %v, want 1..5", order)
	}
}

// Workers are recycled: while every worker is busy another domain waits its turn, and once a
// worker's queue drains it takes the next domain.
func TestDomainWorkersAreRecycledForOtherDomains(t *testing.T) {
	release := make(chan struct{})
	b := newPoolBridge(t, func(outboundJob) { <-release })
	for i := 0; i < outboundWorkers; i++ {
		if !b.enqueue(fmt.Sprintf("d%d.example", i), job(byte(i))) {
			t.Fatalf("domain %d found no worker", i)
		}
	}
	if b.enqueue("waiting.example", job(99)) || b.hasRoom("waiting.example") {
		t.Fatal("a domain got a worker although every worker was busy")
	}
	close(release)
	waitIdle(t, b)
	if !b.enqueue("waiting.example", job(99)) {
		t.Fatal("a recycled worker did not take the waiting domain")
	}
	waitIdle(t, b)
}

// A domain's queue is bounded: past it, messages wait for a later pass rather than blocking.
func TestFullDomainQueueDefersToALaterPass(t *testing.T) {
	release := make(chan struct{})
	b := newPoolBridge(t, func(outboundJob) { <-release })
	defer close(release)
	started := make(chan struct{})
	var once sync.Once
	b.handleJob = func(outboundJob) { once.Do(func() { close(started) }); <-release }
	if !b.enqueue("gmail.com", job(0)) {
		t.Fatal("the first job was not queued")
	}
	<-started // the worker has taken it, so the whole queue is free
	queued := 0
	for n := 1; n <= domainQueueSize+1; n++ {
		if b.enqueue("gmail.com", job(byte(n))) {
			queued++
		}
	}
	if queued != domainQueueSize {
		t.Fatalf("queued %d behind the running job, want %d", queued, domainQueueSize)
	}
	if b.hasRoom("gmail.com") {
		t.Fatal("a full queue reports room")
	}
}

// deferAll is a remote server that always says "come back later".
type deferAll struct{}

func (deferAll) Deliver(context.Context, string, string, *message.PlaintextMessage, Audience) error {
	return fmt.Errorf("%w: 451 later", ErrDeliveryDeferred)
}

// attemptBridge is a bridge with a real outbound handler over deliverer, whose registry says
// alice@dmcn.localhost signs with owner, and one opened message from signer to a legacy address.
func attemptBridge(t *testing.T, deliverer SMTPDeliverer, owner, signer *identity.IdentityKeyPair) (*Bridge, *OpenedMessage) {
	b, opened, _ := attemptBridgeEnv(t, deliverer, owner, signer)
	return b, opened
}

// attemptBridgeEnv is attemptBridge also returning the sealed envelope.
func attemptBridgeEnv(t *testing.T, deliverer SMTPDeliverer, owner, signer *identity.IdentityKeyPair) (*Bridge, *OpenedMessage, *message.EncryptedEnvelope) {
	t.Helper()
	bridgeKP, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b := newRetryBridge()
	b.ctx, b.cancel = context.WithCancel(context.Background())
	t.Cleanup(b.cancel)
	b.bridgeKP = bridgeKP
	b.maxAge = DefaultOutboundMaxAge
	b.log = testLogr()
	b.outbound = NewOutboundHandler(OutboundConfig{
		BridgeKP:     bridgeKP,
		Deliverer:    deliverer,
		BridgeDomain: "bridge.localhost",
		DMCNDomain:   "dmcn.localhost",
		Lookup: func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
			return &identity.IdentityRecord{Address: addr, Ed25519Public: owner.Ed25519Public, X25519Public: owner.X25519Public}, nil
		},
		Log: b.log,
	})
	msg, err := message.NewPlaintextMessage("alice@dmcn.localhost", "ext@gmail.com", "Hi", "hello", signer.Ed25519Public)
	if err != nil {
		t.Fatal(err)
	}
	sm := &message.SignedMessage{Plaintext: *msg}
	if err := sm.Sign(signer.Ed25519Private); err != nil {
		t.Fatal(err)
	}
	env, err := message.Encrypt(sm, []message.RecipientInfo{{DeviceID: signer.DeviceID, X25519Pub: bridgeKP.X25519Public}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := b.outbound.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	return b, opened, env
}

func mustKP(t *testing.T) *identity.IdentityKeyPair {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// An attempt cut short because the bridge is stopping is not a verdict: even past its lifetime
// the message stays queued for the restart, instead of being dropped with a notice that could no
// longer be sent.
func TestStoppingKeepsAMessageQueued(t *testing.T) {
	alice := mustKP(t)
	b, opened := attemptBridge(t, deferAll{}, alice, alice)
	b.cancel()
	if b.attempt(opened, [32]byte{1}, time.Now().Add(-2*DefaultOutboundMaxAge)) {
		t.Fatal("a message was finished while the bridge was stopping")
	}
}

// A message whose signing key is not its named sender's is retried for an hour, in case the record
// is one a key rotation has replaced, and then dropped without telling anyone.
func TestKeyMismatchIsGivenUpAfterAnHour(t *testing.T) {
	alice, forger := mustKP(t), mustKP(t)
	b, opened := attemptBridge(t, &StubSMTPDeliverer{}, alice, forger)

	if b.attempt(opened, [32]byte{1}, time.Now().Add(-10*time.Minute)) {
		t.Fatal("a key mismatch was given up on inside its hour")
	}
	if !b.attempt(opened, [32]byte{2}, time.Now().Add(-2*time.Hour)) {
		t.Fatal("a key mismatch was still retried after its hour")
	}
}

// A failed mailbox listing is not an empty mailbox: the retry schedule of what is backing off
// survives it, rather than everything going out again at once.
func TestFailedListingKeepsTheRetrySchedule(t *testing.T) {
	b := newPoolBridge(t, func(outboundJob) {})
	hash := [32]byte{5}
	b.deferRetry(hash)
	b.dispatch(nil, false)
	if _, ok := b.retries[hash]; !ok {
		t.Fatal("a failed listing wiped the retry schedule")
	}
	b.dispatch(nil, true)
	if _, ok := b.retries[hash]; ok {
		t.Fatal("a complete listing kept the schedule of something no longer queued")
	}
}

// A message whose lifetime runs out while every worker is busy is given up on by the pass itself,
// and its sender told, rather than waiting until the relay drops it without a word.
func TestExpiredMessageIsGivenUpWithoutAWorker(t *testing.T) {
	alice := mustKP(t)
	b, _, env := attemptBridgeEnv(t, deferAll{}, alice, alice)
	b.pool = newWorkerPool()
	b.wake = make(chan struct{}, 1)
	var noticeTo string
	b.deliver = func(_ context.Context, to *identity.IdentityRecord, _ *message.EncryptedEnvelope) error {
		noticeTo = to.Address
		return nil
	}
	release := make(chan struct{})
	b.handleJob = func(outboundJob) { <-release }
	t.Cleanup(func() { close(release); b.cancel(); b.work.Wait() })
	for i := 0; i < outboundWorkers; i++ { // every worker busy with another domain
		if !b.enqueue(fmt.Sprintf("d%d.example", i), job(byte(i))) {
			t.Fatal("could not occupy the workers")
		}
	}

	removed := false
	b.dispatch([]outboundItem{{
		hash:     [32]byte{9},
		queuedAt: time.Now().Add(-2 * DefaultOutboundMaxAge),
		load:     func() (*message.EncryptedEnvelope, error) { return env, nil },
		remove:   func() error { removed = true; return nil },
	}}, true)
	if !removed {
		t.Fatal("a message past its lifetime was left waiting for a worker")
	}
	if noticeTo != "alice@dmcn.localhost" {
		t.Fatalf("the failure notice went to %q, want alice", noticeTo)
	}
}

// What the outbound handler remembers about a message being retried goes when the message leaves
// the queue some other way, not only when the bridge finishes with it.
func TestRetryRecordGoesWithItsMessage(t *testing.T) {
	b := newPoolBridge(t, func(outboundJob) {})
	b.outbound = NewOutboundHandler(OutboundConfig{Log: testLogr()})
	id, rcpt := [16]byte{1}, "ext@gmail.com"
	b.outbound.retrying.update(id, rcpt, func(r *retryRecord) { r.passed = limitHourly })
	b.routed[[32]byte{7}] = routedMessage{domain: "gmail.com", msgID: id, recipient: rcpt}

	b.dispatch(nil, true) // the envelope is no longer queued
	if got := b.outbound.retrying.get(id, rcpt); got.passed != 0 {
		t.Fatal("the retry record outlived its message")
	}
}
