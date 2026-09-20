package identity

import (
	"errors"
	"testing"
	"time"
)

// rotDomain is the domain every fixture here lives on, matching rotAddr in rotation_test.go.
const rotDomain = "dmcn.email"

// rotFixture is one account mid-rotation: the record being displaced, the record asking to
// displace it, and the domain both live under.
type rotFixture struct {
	dar      *DomainAuthorityRecord
	root     *IdentityKeyPair
	prev     *IdentityRecord
	next     *IdentityRecord
	entry    *RotationEntry
	now      time.Time
	deviceKP *IdentityKeyPair
	oldKP    *IdentityKeyPair
	newKP    *IdentityKeyPair
}

// deviceCredential mints and signs a device credential for `addr`, enrolled `enrolledAgo` before
// the rotation. The domain root issues it directly, which is what the pairing ceremony will do.
func deviceCredential(t *testing.T, root, device *IdentityKeyPair, addr string, issuedAt time.Time) *Credential {
	t.Helper()
	cred := &Credential{
		Version: 1, Subject: device.Ed25519Public, Domain: rotDomain, Address: addr,
		Roles: []string{RoleDevice}, IssuedAt: issuedAt.UTC(),
	}
	if err := cred.Sign(root); err != nil {
		t.Fatalf("sign device credential: %v", err)
	}
	return cred
}

// newRotFixture builds a rotation that SHOULD be authorized, so each test can break exactly one
// thing and watch the arm refuse.
func newRotFixture(t *testing.T, flags uint32, enrolledAgo time.Duration) *rotFixture {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	root, oldKP, newKP, device := mustKP(t), mustKP(t), mustKP(t), mustKP(t)

	// The domain root has to predate everything it signs: AuthorityEffectiveFrom comes from the
	// root key's own CreatedAt, and a credential issued before the root existed resolves to no
	// issuer at all. A real domain is years older than any device enrolled under it.
	root.CreatedAt = now.Add(-365 * 24 * time.Hour)

	dar, err := NewDomainAuthorityRecord(rotDomain, root, now.Add(-365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dar.PolicyFlags = flags
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}

	prev := genesisRecord(t, oldKP)
	next, err := NewIdentityRecord(rotAddr, newKP)
	if err != nil {
		t.Fatal(err)
	}
	next.Revision = prev.Revision + 1

	e, err := NewRotationEntry(prev, newKP.Ed25519Public, newKP.X25519Public, next.Revision, now)
	if err != nil {
		t.Fatal(err)
	}
	e.DeviceCredential = deviceCredential(t, root, device, rotAddr, now.Add(-enrolledAgo))
	if err := e.SignDevice(device.Ed25519Private); err != nil {
		t.Fatal(err)
	}
	if err := e.SignConsent(oldKP); err != nil {
		t.Fatal(err)
	}
	if err := e.SignAcceptance(newKP); err != nil {
		t.Fatal(err)
	}
	next.RotationChain = AppendRotation(prev, e)
	if err := next.Sign(newKP); err != nil {
		t.Fatal(err)
	}
	return &rotFixture{dar: dar, root: root, prev: prev, next: next, entry: &next.RotationChain[0], now: now, deviceKP: device, oldKP: oldKP, newKP: newKP}
}

const allowRotation = PolicyAllowKeyRotation

func TestAuthorizeRebindOwnerRotation(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	arm, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now)
	if err != nil {
		t.Fatalf("a well-formed owner rotation should be authorized: %v", err)
	}
	if arm != RebindOwnerRotation {
		t.Fatalf("arm = %q, want %q", arm, RebindOwnerRotation)
	}
}

// TestAuthorizeRebindRotationNeedsDomainOptIn: the capability is off until a domain's root
// ceremony turns it on, and every DAR already published leaves it off.
func TestAuthorizeRebindRotationNeedsDomainOptIn(t *testing.T) {
	f := newRotFixture(t, 0, 60*24*time.Hour)
	_, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now)
	if !errors.Is(err, ErrRebindRotationNotAllowed) {
		t.Fatalf("err = %v, want ErrRebindRotationNotAllowed", err)
	}
}

// TestAuthorizeRebindRotationNeedsDevice is the property the whole scheme rests on: a stolen
// ACCOUNT key is not enough, because device keys never leave their device.
func TestAuthorizeRebindRotationNeedsDevice(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(t *testing.T, f *rotFixture)
	}{
		{"no device attested it", func(t *testing.T, f *rotFixture) {
			f.entry.DeviceCredential = nil
			f.entry.DeviceSignature = nil
		}},
		{"the device credential is for another account", func(t *testing.T, f *rotFixture) {
			f.entry.DeviceCredential = deviceCredential(t, f.root, f.deviceKP, "mallory@dmcn.email", f.now.Add(-60*24*time.Hour))
		}},
		{"the credential is not a device credential", func(t *testing.T, f *rotFixture) {
			f.entry.DeviceCredential.Roles = []string{RoleRouting}
			if err := f.entry.DeviceCredential.Sign(f.root); err != nil {
				t.Fatal(err)
			}
		}},
		{"the device credential was issued by a stranger", func(t *testing.T, f *rotFixture) {
			if err := f.entry.DeviceCredential.Sign(mustKP(t)); err != nil {
				t.Fatal(err)
			}
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newRotFixture(t, allowRotation, 60*24*time.Hour)
			tc.break_(t, f)
			if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now); err == nil {
				t.Fatal("rotation authorized, want refusal")
			}
		})
	}
}

// TestAuthorizeRebindRotationLiftedDeviceCredential: a credential is public once published, so
// an attacker holding the account key could copy one. Only the device's SIGNATURE over this
// transition stops that, and they cannot produce it.
func TestAuthorizeRebindRotationLiftedDeviceCredential(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	// Keep the genuine credential; forge everything the thief could: they hold the old account
	// key, so they can consent and accept, but they cannot sign as the device.
	f.entry.DeviceSignature = nil
	if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now); err == nil {
		t.Fatal("a lifted device credential with no device signature was accepted")
	}
}

// TestAuthorizeRebindRotationDeviceTenure: enrolling a device buys an attacker a wait, not an
// immediate takeover — and the wait is when the device shows up in the owner's list.
func TestAuthorizeRebindRotationDeviceTenure(t *testing.T) {
	fresh := newRotFixture(t, allowRotation, time.Hour)
	if _, err := AuthorizeRebind(fresh.prev, fresh.next, nil, fresh.dar, fresh.now); err == nil {
		t.Fatal("a device enrolled an hour ago should not clear the default minimum")
	}

	// A domain may set its own minimum, and a device that clears it is fine.
	relaxed := newRotFixture(t, allowRotation, 48*time.Hour)
	relaxed.dar.RotationMinDeviceAgeDays = 1
	if err := relaxed.dar.Sign(relaxed.root); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeRebind(relaxed.prev, relaxed.next, nil, relaxed.dar, relaxed.now); err != nil {
		t.Fatalf("a 48h-old device should clear a 1-day minimum: %v", err)
	}
}

// TestAuthorizeRebindRotationFutureDated: tenure is measured between two timestamps the rotating
// party chooses — when the device credential says it was issued, and when the entry says the
// rotation happened. Neither is checked against the world by the chain walk, which compares
// entries only with each other. So the node's own clock has to bound the entry, or a device
// enrolled minutes ago clears any minimum a domain can set simply by dating the transition far
// enough ahead.
func TestAuthorizeRebindRotationFutureDated(t *testing.T) {
	f := newRotFixture(t, allowRotation, time.Hour)
	ahead := f.now.Add(400 * 24 * time.Hour)

	e, err := NewRotationEntry(f.prev, f.newKP.Ed25519Public, f.newKP.X25519Public, f.next.Revision, ahead)
	if err != nil {
		t.Fatal(err)
	}
	e.DeviceCredential = f.entry.DeviceCredential // the genuine credential, issued an hour ago
	if err := e.SignDevice(f.deviceKP.Ed25519Private); err != nil {
		t.Fatal(err)
	}
	if err := e.SignConsent(f.oldKP); err != nil {
		t.Fatal(err)
	}
	if err := e.SignAcceptance(f.newKP); err != nil {
		t.Fatal(err)
	}
	f.next.RotationChain = AppendRotation(f.prev, e)
	if err := f.next.Sign(f.newKP); err != nil {
		t.Fatal(err)
	}

	// Every signature here is genuine and the arithmetic says 400 days of tenure. The only thing
	// wrong with it is that it has not happened yet.
	if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now); err == nil {
		t.Fatal("a rotation dated 400 days ahead cleared the tenure minimum")
	}
	// And the bound is about the clock rather than the dates: judged by a node that really is
	// 400 days later, the device really has served its tenure and the same record is admitted.
	if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, ahead); err != nil {
		t.Fatalf("the same rotation, judged at the time it names: %v", err)
	}
}

// TestAuthorizeRebindRotationAnchoring: a genuine chain must not be a transferable capability.
func TestAuthorizeRebindRotationAnchoring(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	// Someone else's record, displaced by a chain that never mentions it.
	other := genesisRecord(t, mustKP(t))
	if _, err := AuthorizeRebind(other, f.next, nil, f.dar, f.now); err == nil {
		t.Fatal("a chain anchored on another record authorized this rebind")
	}
}

// TestAuthorizeRebindRotationRecoveryKeyMustBeThePriorRecordS: the recovery key is read off the
// record being DISPLACED. Reading it from the incoming one would let an attacker name their own.
func TestAuthorizeRebindRotationRecoveryKeyMustBeThePriorRecordS(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	attacker := mustKP(t)

	// The attacker consents with a key of their own and advertises it as "recovery" on the
	// record they are pushing.
	f.entry.DeviceCredential = deviceCredential(t, f.root, f.deviceKP, rotAddr, f.now.Add(-60*24*time.Hour))
	f.entry.AuthorizingEd25519Public = attacker.Ed25519Public
	if err := f.entry.SignDevice(f.deviceKP.Ed25519Private); err != nil {
		t.Fatal(err)
	}
	if err := f.entry.SignConsent(attacker); err != nil {
		t.Fatal(err)
	}
	f.next.RecoveryEd25519Public = attacker.Ed25519Public
	if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now); err == nil {
		t.Fatal("a recovery key named by the INCOMING record authorized the rebind")
	}
}

// TestAuthorizeRebindRootTombstoneOutranksRotation: an offboarded key whose binding the root
// freed must not be able to argue its way back by presenting a chain.
func TestAuthorizeRebindRootTombstoneOutranksRotation(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	rm, err := NewAddressRemovalRecord(rotDomain, rotAddr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = []RemovedBinding{{Ed25519Public: f.prev.Ed25519Public, RemovedAt: f.now}}
	if err := rm.Sign(f.root); err != nil {
		t.Fatal(err)
	}
	arm, err := AuthorizeRebind(f.prev, f.next, rm, f.dar, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if arm != RebindRootTombstone {
		t.Fatalf("arm = %q, want the operator arm to win when both apply", arm)
	}
}

// TestAuthorizeRebindRotationIntoTombstonedKey: a key the root has tombstoned must not be
// brought back by a rotation the owner signs on its behalf.
func TestAuthorizeRebindRotationIntoTombstonedKey(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	rm, err := NewAddressRemovalRecord(rotDomain, rotAddr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = []RemovedBinding{{Ed25519Public: f.next.Ed25519Public, RemovedAt: f.now}}
	if err := rm.Sign(f.root); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeRebind(f.prev, f.next, rm, f.dar, f.now); err == nil {
		t.Fatal("rotation into a root-tombstoned key was authorized")
	}
}

// TestAuthorizeRebindRotationNeedsDAR: the policy bits live in the DAR, so a node missing one
// cannot evaluate the arm and must not fall through to allowing it.
func TestAuthorizeRebindRotationNeedsDAR(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	if _, err := AuthorizeRebind(f.prev, f.next, nil, nil, f.now); !errors.Is(err, ErrRebindUnverifiable) {
		t.Fatalf("err = %v, want ErrRebindUnverifiable with no DAR", err)
	}
}

// TestAuthorizeRebindRotationRevisionMustAdvance keeps the arm from being a rollback vector.
func TestAuthorizeRebindRotationRevisionMustAdvance(t *testing.T) {
	f := newRotFixture(t, allowRotation, 60*24*time.Hour)
	f.prev.Revision = f.next.Revision + 5
	if _, err := AuthorizeRebind(f.prev, f.next, nil, f.dar, f.now); err == nil {
		t.Fatal("a rotation that does not advance the revision was authorized")
	}
}
