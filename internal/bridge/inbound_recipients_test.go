package bridge_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// multiStore records every envelope the inbound handler delivered, by recipient address.
type multiStore struct {
	mu   sync.Mutex
	envs map[string][]*message.EncryptedEnvelope
	fail map[string]error // recipient address → delivery error
}

func (m *multiStore) fn(_ context.Context, rec *identity.IdentityRecord, env *message.EncryptedEnvelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail[rec.Address]; err != nil {
		return err
	}
	if m.envs == nil {
		m.envs = map[string][]*message.EncryptedEnvelope{}
	}
	m.envs[rec.Address] = append(m.envs[rec.Address], env)
	return nil
}

// keyring is a stub registry: address → key pair.
type keyring map[string]*identity.IdentityKeyPair

func (k keyring) lookup(_ context.Context, addr string) (*identity.IdentityRecord, error) {
	kp, ok := k[addr]
	if !ok {
		return nil, errors.New("not registered")
	}
	return recordFor(addr, kp), nil
}

func openHeader(t *testing.T, env *message.EncryptedEnvelope, kp *identity.IdentityKeyPair) *message.SignedHeader {
	t.Helper()
	sh, err := message.DecryptHeader(env, kp.X25519Private, kp.X25519Public)
	if err != nil {
		t.Fatalf("decrypt header (verifies bridge signature): %v", err)
	}
	return sh
}

const introMail = "From: Carol <carol@gmail.com>\r\n" +
	"To: Alice <alice@bridge.localhost>, dave@example.org\r\n" +
	"Cc: bob@bridge.localhost\r\n" +
	"Subject: Intro\r\n" +
	"Message-ID: <intro-1@gmail.com>\r\n" +
	"\r\n" +
	"Alice, meet Dave.\r\n"

// One SMTP transaction naming two of our users delivers a copy to EACH — every RCPT TO, not the
// last one — and each copy's signed header carries the mail's visible To/Cc, with bridge-domain
// addresses mapped to their DMCN form and outside addresses as written.
func TestInboundDeliversEveryRecipientWithAudience(t *testing.T) {
	keys := keyring{"alice@dmcn.localhost": mustKeyPair(t), "bob@dmcn.localhost": mustKeyPair(t)}
	store := &multiStore{}
	h := newInbound(passingAuth(), keys.lookup, store.fn, mustKeyPair(t))

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "carol@gmail.com",
		[]string{"alice@bridge.localhost", "bob@bridge.localhost"}, []byte(introMail)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	wantTo := []string{"alice@dmcn.localhost", "dave@example.org"}
	wantCc := []string{"bob@dmcn.localhost"}
	var mids [][16]byte
	for addr, kp := range keys {
		envs := store.envs[addr]
		if len(envs) != 1 {
			t.Fatalf("%s: got %d copies, want 1", addr, len(envs))
		}
		sh := openHeader(t, envs[0], kp)
		if sh.Header.RecipientAddress != addr {
			t.Errorf("%s: recipient_address %q", addr, sh.Header.RecipientAddress)
		}
		if !slices.Equal(sh.Header.To, wantTo) || !slices.Equal(sh.Header.Cc, wantCc) {
			t.Errorf("%s: audience to=%v cc=%v, want to=%v cc=%v", addr, sh.Header.To, sh.Header.Cc, wantTo, wantCc)
		}
		if sh.Header.SenderAddress != "carol@gmail.com" || sh.Header.Subject != "Intro" {
			t.Errorf("%s: sender %q subject %q", addr, sh.Header.SenderAddress, sh.Header.Subject)
		}
		// The body must still match the header each copy was re-signed with.
		if _, err := message.DecryptBody(envs[0], &sh.Header, kp.X25519Private, kp.X25519Public); err != nil {
			t.Fatalf("%s: decrypt body: %v", addr, err)
		}
		mids = append(mids, sh.Header.MessageID)
	}
	if mids[0] != mids[1] {
		t.Error("copies of one message must share its message ID")
	}
}

// Two RCPTs that reach one mailbox (the same address named twice, or an address and its shared
// alias) deliver one copy, not two.
func TestInboundOneCopyPerMailbox(t *testing.T) {
	kp := mustKeyPair(t)
	keys := keyring{"alice@dmcn.localhost": kp, "sales@dmcn.localhost": kp}
	store := &multiStore{}
	h := newInbound(passingAuth(), keys.lookup, store.fn, mustKeyPair(t))

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "carol@gmail.com",
		[]string{"alice@bridge.localhost", "sales@bridge.localhost", "alice@bridge.localhost"}, []byte(introMail)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	total := 0
	for _, envs := range store.envs {
		total += len(envs)
	}
	if total != 1 {
		t.Fatalf("got %d copies into one mailbox, want 1", total)
	}
}

// When some copies are delivered and another fails, the transaction is accepted: failing it
// would make the sender retry and duplicate the copies already delivered. When none are
// delivered, the failure is returned.
func TestInboundPartialDeliveryAccepts(t *testing.T) {
	keys := keyring{"alice@dmcn.localhost": mustKeyPair(t), "bob@dmcn.localhost": mustKeyPair(t)}
	boom := errors.New("relay unreachable")

	store := &multiStore{fail: map[string]error{"bob@dmcn.localhost": boom}}
	h := newInbound(passingAuth(), keys.lookup, store.fn, mustKeyPair(t))
	if err := h.HandleMessage(context.Background(), "1.2.3.4", "carol@gmail.com",
		[]string{"alice@bridge.localhost", "bob@bridge.localhost"}, []byte(introMail)); err != nil {
		t.Fatalf("partial delivery must be accepted, got %v", err)
	}
	if len(store.envs["alice@dmcn.localhost"]) != 1 {
		t.Fatal("alice's copy must be delivered")
	}

	store = &multiStore{fail: map[string]error{"alice@dmcn.localhost": boom, "bob@dmcn.localhost": boom}}
	h = newInbound(passingAuth(), keys.lookup, store.fn, mustKeyPair(t))
	err := h.HandleMessage(context.Background(), "1.2.3.4", "carol@gmail.com",
		[]string{"alice@bridge.localhost", "bob@bridge.localhost"}, []byte(introMail))
	if !errors.Is(err, boom) {
		t.Fatalf("all copies failing must fail the transaction, got %v", err)
	}
}

// A header block that names no To/Cc (or does not parse) yields an empty audience, not an error.
func TestInboundNoAudience(t *testing.T) {
	kp := mustKeyPair(t)
	keys := keyring{"alice@dmcn.localhost": kp}
	store := &multiStore{}
	h := newInbound(passingAuth(), keys.lookup, store.fn, mustKeyPair(t))
	if err := h.HandleMessage(context.Background(), "1.2.3.4", "carol@gmail.com",
		[]string{"alice@bridge.localhost"}, []byte("hi")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	sh := openHeader(t, store.envs["alice@dmcn.localhost"][0], kp)
	if len(sh.Header.To) != 0 || len(sh.Header.Cc) != 0 {
		t.Fatalf("audience to=%v cc=%v, want none", sh.Header.To, sh.Header.Cc)
	}
}

var _ bridge.DeliverFunc = (&multiStore{}).fn
