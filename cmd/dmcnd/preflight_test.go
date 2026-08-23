package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// TestPreflightAcceptsAFreePort keeps the happy path honest: the check must not itself be the
// thing that fails, and must leave the port free for the real listener a moment later.
func TestPreflightAcceptsAFreePort(t *testing.T) {
	if err := preflightListen("127.0.0.1:0"); err != nil {
		t.Fatalf("a free port was rejected: %v", err)
	}
}

// TestPreflightDetectsAPortInUse covers the case an operator hits when a previous dmcnd is still
// running, or a web server already owns the port.
func TestPreflightDetectsAPortInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = preflightListen(l.Addr().String())
	if err == nil {
		t.Fatal("an occupied port passed the preflight")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("unhelpful message: %v", err)
	}
	if !strings.Contains(err.Error(), "ss -lntp") {
		t.Errorf("message does not say how to find the culprit: %v", err)
	}
}

// TestPermissionDeniedExplainsTheThreeWaysOut is the one that matters and the one that cannot be
// reproduced here: this sandbox, like most containers, lets an unprivileged user bind port 443. On
// a normal host it is the first thing an operator hits after the default moved to :443, so the
// message has to carry every route out — including WHY the default is 443, or the obvious
// "just use another port" leads straight into autocert silently never working.
func TestPermissionDeniedExplainsTheThreeWaysOut(t *testing.T) {
	err := explainListenError(":443", fmt.Errorf("listen tcp :443: bind: %w", os.ErrPermission))
	if err == nil {
		t.Fatal("permission denied was not reported as an error")
	}
	msg := err.Error()
	for _, want := range []string{
		"setcap",                 // grant it to the binary
		"AmbientCapabilities",    // or to the systemd unit
		"DMCND_TLS_CERT",         // or move off 443 and bring your own certificate
		"automatic certificates", // why 443 is the default at all
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message omits %q:\n%s", want, msg)
		}
	}
}

// TestPermissionDeniedMatchesTheRealErrorText guards the detection itself. Go's bind error wraps
// syscall.EPERM/EACCES, and a string match on "permission denied" is the fallback — if neither
// fires, the operator gets the raw error and none of the advice above.
func TestPermissionDeniedMatchesTheRealErrorText(t *testing.T) {
	// Shaped exactly like the runtime error: "listen tcp :443: bind: permission denied".
	raw := errors.New("listen tcp :443: bind: permission denied")
	if !strings.Contains(explainListenError(":443", raw).Error(), "setcap") {
		t.Error("a bind error carrying only the text form was not recognised as a permission problem")
	}
}

// TestUnknownFailureIsNotSwallowed: an error nobody anticipated must still surface, with the
// address, rather than being reported as one of the two cases above.
func TestUnknownFailureIsNotSwallowed(t *testing.T) {
	err := explainListenError(":443", errors.New("no such device"))
	if err == nil {
		t.Fatal("an unknown bind failure was reported as success")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no such device") || !strings.Contains(msg, ":443") {
		t.Errorf("message lost the cause or the address: %s", msg)
	}
	if strings.Contains(msg, "setcap") {
		t.Errorf("an unrelated failure was explained as a permissions problem: %s", msg)
	}
}
