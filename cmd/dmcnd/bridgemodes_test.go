package main

import (
	"strings"
	"testing"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
)

func modeLogger() logr.Logger { return logr.With(logr.M("component", "test")) }

// The regression this guards: for the whole life of the daemon before this, neither
// DNSAuthVerifier nor SMTPSender had a single non-test caller and no environment variable reached
// them, so the bridge ALWAYS ran the dev stubs — while the docs claimed inbound mail was checked
// with SPF/DKIM/DMARC. Unreachable code is invisible to every other test, so assert the wiring.
func TestApplyBridgeModesDefaults(t *testing.T) {
	var bcfg bridge.Config
	cfg := config{bridgeAuthMode: "dns", bridgeDelivery: "stub"}
	if err := applyBridgeModes(&bcfg, cfg, modeLogger()); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
	// Inbound verification must be REAL by default — the signed verdict the recipient's client
	// checks is worthless if it came from a stub.
	if bcfg.AuthVerifier == nil {
		t.Fatal("default auth mode left the verifier nil — the bridge would silently stub SPF/DKIM/DMARC")
	}
	if _, ok := bcfg.AuthVerifier.(*bridge.DNSAuthVerifier); !ok {
		t.Fatalf("default auth verifier is %T, want *bridge.DNSAuthVerifier", bcfg.AuthVerifier)
	}
	// Outbound must NOT send by default: installing the daemon must never start emitting live mail.
	if bcfg.Deliverer != nil {
		t.Fatal("default delivery mode installed a real deliverer — a fresh install would send live mail")
	}
}

func TestApplyBridgeModesOptIns(t *testing.T) {
	t.Run("auth stub is available but explicit", func(t *testing.T) {
		var bcfg bridge.Config
		cfg := config{bridgeAuthMode: "stub", bridgeDelivery: "stub"}
		if err := applyBridgeModes(&bcfg, cfg, modeLogger()); err != nil {
			t.Fatal(err)
		}
		if bcfg.AuthVerifier != nil {
			t.Fatal("stub mode should leave the verifier nil for bridge.New to fill")
		}
	})

	t.Run("real outbound delivery is reachable", func(t *testing.T) {
		var bcfg bridge.Config
		cfg := config{bridgeAuthMode: "dns", bridgeDelivery: "smtp", bridgeDomain: "mesh.example"}
		if err := applyBridgeModes(&bcfg, cfg, modeLogger()); err != nil {
			t.Fatal(err)
		}
		if _, ok := bcfg.Deliverer.(*bridge.SMTPSender); !ok {
			t.Fatalf("delivery mode smtp gave %T, want *bridge.SMTPSender", bcfg.Deliverer)
		}
	})

	t.Run("unknown modes are rejected, not silently stubbed", func(t *testing.T) {
		for _, c := range []config{
			{bridgeAuthMode: "off", bridgeDelivery: "stub"},
			{bridgeAuthMode: "dns", bridgeDelivery: "send"},
		} {
			var bcfg bridge.Config
			err := applyBridgeModes(&bcfg, c, modeLogger())
			if err == nil {
				t.Fatalf("config %+v accepted", c)
			}
			if !strings.Contains(err.Error(), "invalid") {
				t.Fatalf("unhelpful error: %v", err)
			}
		}
	})
}
