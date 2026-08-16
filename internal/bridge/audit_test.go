package bridge_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// capturingAudit collects events in memory.
type capturingAudit struct {
	mu     sync.Mutex
	events []bridge.AuditEvent
}

func (c *capturingAudit) Record(ev bridge.AuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *capturingAudit) byAction(action string) *bridge.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.events {
		if c.events[i].Action == action {
			return &c.events[i]
		}
	}
	return nil
}

// A successful inbound delivery emits an inbound.deliver audit event carrying the
// classified trust tier.
func TestAuditInboundDeliver(t *testing.T) {
	audit := &capturingAudit{}
	recipientKP := mustKeyPair(t)
	store := &capturingStore{}
	h := bridge.NewInboundHandler(bridge.InboundConfig{
		BridgeKP:     mustKeyPair(t),
		BridgeAddr:   tBridgeAddr,
		AuthVerifier: passingAuth(),
		Lookup: func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
			return recordFor(addr, recipientKP), nil
		},
		Deliver:      store.fn,
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Audit:        audit,
		Log:          testLog(),
	})

	if err := h.HandleMessage(context.Background(), "1.2.3.4", "ext@gmail.com", "alice@bridge.localhost", []byte("From: ext@gmail.com\r\n\r\nhi")); err != nil {
		t.Fatalf("handle: %v", err)
	}
	ev := audit.byAction("inbound.deliver")
	if ev == nil {
		t.Fatal("expected an inbound.deliver audit event")
	}
	if !ev.Success || ev.To != "alice@dmcn.localhost" || ev.TrustTier != bridge.TrustTierVerifiedLegacy {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

// An outbound delivery emits an outbound.deliver event; the FileAuditLog persists
// it as a JSON line.
func TestFileAuditLogPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	al, err := bridge.NewFileAuditLog(path, nil, testLog())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	bridgeKP := mustKeyPair(t)
	senderKP := mustKeyPair(t)
	env := sealedToBridge(t, senderKP, bridgeKP, "alice@dmcn.localhost", "ext@gmail.com", "hi")
	h := bridge.NewOutboundHandler(bridge.OutboundConfig{
		BridgeKP:   bridgeKP,
		BridgeAddr: tBridgeAddr,
		Deliverer:  &bridge.StubSMTPDeliverer{},
		Lookup: func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
			return recordFor(addr, senderKP), nil
		},
		BridgeDomain: tBridgeDomain,
		DMCNDomain:   tDMCNDomain,
		Audit:        al,
		Log:          testLog(),
	})
	if _, err := h.HandleEnvelope(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	al.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	defer f.Close()
	var found bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev bridge.AuditEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("bad JSON line: %v", err)
		}
		if ev.Action == "outbound.deliver" && ev.Success && ev.To == "ext@gmail.com" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a persisted outbound.deliver audit line")
	}
}
