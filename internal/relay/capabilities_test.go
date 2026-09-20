package relay

import (
	"slices"
	"testing"
)

// TestCapabilitiesAdvertised: a token is a promise about THIS binary, so the list a Ping
// carries must come from the build rather than from configuration a deploy could get wrong.
func TestCapabilitiesAdvertised(t *testing.T) {
	caps := capabilities()
	if !slices.Contains(caps, CapRotationSchema) {
		t.Fatalf("capabilities %v omit %q — this build parses rotation_chain, so it must say so", caps, CapRotationSchema)
	}
	if !slices.Contains(caps, CapRotation) {
		t.Fatalf("capabilities %v omit %q — this build enforces the owner-rotation arm", caps, CapRotation)
	}
	// Enforcing the arm implies understanding the schema, so a build claiming the first while
	// withholding the second would be describing a state that cannot exist.
	if slices.Contains(caps, CapRotation) && !slices.Contains(caps, CapRotationSchema) {
		t.Fatal("a build that authorizes rotations must also advertise schema support")
	}
}

// TestCapabilitiesNotSharedAcrossCalls: a caller that mutated the returned slice would change
// what every future Ping claims about this relay.
func TestCapabilitiesNotSharedAcrossCalls(t *testing.T) {
	first := capabilities()
	first[0] = "tampered"
	if second := capabilities(); second[0] == "tampered" {
		t.Fatal("capabilities() hands out a shared slice; a caller can rewrite what the relay advertises")
	}
}
