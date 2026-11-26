package relay

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"

	"dmcn.dev/open-dmcn/dmcnpb"
)

const devTestRx = "aabbccdd"

func newDeviceStore(t *testing.T) *DeviceStore {
	t.Helper()
	return NewDeviceStore(dssync.MutexWrap(ds.NewMapDatastore()))
}

func devKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestDeviceGenesisOnlyOnce is the rule the whole registry turns on: the FIRST device on an
// empty registry lets itself in, and from then on nobody can. An existing mailbox meeting the
// registry for the first time takes the same path a fresh signup does, which is why migration
// needs no special mode.
func TestDeviceGenesisOnlyOnce(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	first, second := devKey(t), devKey(t)

	rec, genesis, err := s.Enroll(ctx, devTestRx, first, nil, false, 0, false, nil, nil)
	if err != nil {
		t.Fatalf("first device refused: %v", err)
	}
	if !genesis {
		t.Fatal("the first device should report genesis")
	}
	if rec.EnrolledAt == 0 {
		t.Fatal("the relay must stamp an enrolment date")
	}

	// The second device holds the account key too — that is what authenticated the op — and it
	// still cannot let itself in.
	if _, _, err = s.Enroll(ctx, devTestRx, second, nil, false, 0, false, nil, nil); !errors.Is(err, ErrDeviceRegistryClaimed) {
		t.Fatalf("err = %v, want ErrDeviceRegistryClaimed for an unapproved second device", err)
	}
	if _, _, err = s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); err != nil {
		t.Fatalf("an approved second device was refused: %v", err)
	}
}

// TestDeviceGenesisRaceHasOneWinner: two of the owner's devices polling at the same moment both
// see an empty registry. Exactly one may claim it, or the mailbox ends up with two "first"
// devices that never approved each other.
func TestDeviceGenesisRaceHasOneWinner(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()

	const racers = 8
	var wg sync.WaitGroup
	results := make([]bool, racers)
	errs := make([]error, racers)
	keys := make([]ed25519.PublicKey, racers)
	for i := range keys {
		keys[i] = devKey(t)
	}
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func(i int) {
			defer wg.Done()
			_, genesis, err := s.Enroll(ctx, devTestRx, keys[i], nil, false, 0, false, nil, nil)
			results[i], errs[i] = genesis, err
		}(i)
	}
	wg.Wait()

	var won int
	for i := range results {
		if errs[i] == nil && results[i] {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d devices claimed genesis, want exactly 1", won)
	}
	active, err := s.Active(ctx, devTestRx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("%d devices enrolled after the race, want 1", len(active))
	}
}

// TestDeviceRetirementIsATombstone: a device removed by someone holding the account key must
// leave a trace. A silent delete would let an attacker prune the owner's devices invisibly.
func TestDeviceRetirementIsATombstone(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	first, second := devKey(t), devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, first, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}

	rec, err := s.Retire(ctx, devTestRx, first)
	if err != nil {
		t.Fatal(err)
	}
	if rec.RetiredAt == 0 {
		t.Fatal("retirement must stamp a date")
	}
	if s.IsActive(ctx, devTestRx, first) {
		t.Fatal("a retired device should not read as active")
	}

	all, err := s.List(ctx, devTestRx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("List returned %d devices, want the tombstone to survive alongside the live one", len(all))
	}
	active, err := s.Active(ctx, devTestRx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 {
		t.Fatalf("Active returned %d devices, want the one still enrolled", len(active))
	}
}

// TestDeviceRetiredKeyStaysOut: a removed device key cannot be enrolled again, even approved, and
// says so distinctly. Re-admitting it would erase the owner's removal; reporting it as "already
// enrolled" would tell the removed browser it was fine.
func TestDeviceRetiredKeyStaysOut(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	first, second := devKey(t), devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, first, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, devTestRx, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, first, nil, true, 0, false, nil, nil); !errors.Is(err, ErrDeviceRetired) {
		t.Fatalf("re-enrolling a removed key: err = %v, want ErrDeviceRetired", err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("re-enrolling a live key: err = %v, want ErrDeviceExists", err)
	}
}

// TestDeviceErrorPhrasesTheBrowserMatches pins the words the web client reads. The mailbox proxy
// forwards the relay's own sentence and the browser matches a phrase in it (deviceRegistry.ts,
// whose tests carry the same strings), so rewording one of these silently breaks the other side.
func TestDeviceErrorPhrasesTheBrowserMatches(t *testing.T) {
	for err, phrase := range map[error]string{
		ErrDeviceApprovalRequired: "needs approval from a device",
		ErrDeviceNotEnrolled:      "requires a proof from an enrolled device",
		ErrDeviceRecoveryDisabled: "does not let a device join without approval",
	} {
		if !strings.Contains(err.Error(), phrase) {
			t.Errorf("%q no longer contains %q, which the browser matches", err, phrase)
		}
	}
}

// TestDeviceLastActiveCannotBeRetired is the invariant the registry's safety rests on: a mailbox
// always keeps at least one enrolled device. With none, no newcomer could ever be approved, and
// the only way back in would be to reopen enrolment to whoever holds the account key — which is
// precisely what the registry exists to prevent.
func TestDeviceLastActiveCannotBeRetired(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	only := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, only, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, devTestRx, only); !errors.Is(err, ErrDeviceLastActive) {
		t.Fatalf("err = %v, want ErrDeviceLastActive", err)
	}

	// Enrol a replacement and the original becomes retirable — the supported order is add, then
	// remove, never the other way round.
	second := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, devTestRx, only); err != nil {
		t.Fatalf("retiring a device with a replacement enrolled: %v", err)
	}
	// And now the replacement is the last one, so it is protected in turn.
	if _, err := s.Retire(ctx, devTestRx, second); !errors.Is(err, ErrDeviceLastActive) {
		t.Fatalf("err = %v, want the last remaining device to be protected too", err)
	}
}

// TestDeviceRetirementIsIdempotent: retiring twice must not move the date, or a second attempt
// could rewrite when a device actually lost access.
func TestDeviceRetirementIsIdempotent(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	s.SetClock(func() time.Time { return at })

	d := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, d, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, true, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	first, err := s.Retire(ctx, devTestRx, d)
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return at.Add(72 * time.Hour) })
	second, err := s.Retire(ctx, devTestRx, d)
	if err != nil {
		t.Fatal(err)
	}
	if first.RetiredAt != second.RetiredAt {
		t.Fatalf("retirement date moved on a second attempt: %d then %d", first.RetiredAt, second.RetiredAt)
	}
}

// TestDeviceTombstoneDoesNotReopenGenesis: genesis means the registry has NEVER held a device,
// so a tombstone keeps it claimed. Belt and braces behind the last-active invariant — that rule
// makes an empty registry unreachable, and this one makes an empty registry harmless even if a
// future path ever produced it.
func TestDeviceTombstoneDoesNotReopenGenesis(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	first, second := devKey(t), devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, first, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, second, nil, true, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, devTestRx, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, 0, false, nil, nil); !errors.Is(err, ErrDeviceRegistryClaimed) {
		t.Fatalf("err = %v — a registry holding a tombstone must stay claimed", err)
	}
}

func TestDeviceEnrollRejectsDuplicatesAndShortKeys(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	d := devKey(t)
	if _, _, err := s.Enroll(ctx, devTestRx, d, nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, d, nil, true, 0, false, nil, nil); !errors.Is(err, ErrDeviceExists) {
		t.Fatalf("err = %v, want ErrDeviceExists", err)
	}
	if _, _, err := s.Enroll(ctx, devTestRx, []byte{0x01, 0x02}, nil, false, 0, false, nil, nil); err == nil {
		t.Fatal("a short device key was accepted")
	}
}

// TestDeviceListOrderIsDeterministic: two replicas listing the same registry must agree on
// which device is eldest, since that is what a tenure rule reads.
func TestDeviceListOrderIsDeterministic(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 5; i++ {
		s.SetClock(func() time.Time { return base.Add(time.Duration(i) * time.Hour) })
		if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, i > 0, 0, false, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.List(ctx, devTestRx)
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 5; run++ {
		again, lerr := s.List(ctx, devTestRx)
		if lerr != nil {
			t.Fatal(lerr)
		}
		for i := range first {
			if string(first[i].Ed25519PublicKey) != string(again[i].Ed25519PublicKey) {
				t.Fatal("device list order is not stable across calls")
			}
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i].EnrolledAt < first[i-1].EnrolledAt {
			t.Fatal("device list should be oldest enrolment first")
		}
	}
}

func TestDeviceRegistryIsPerMailbox(t *testing.T) {
	s := newDeviceStore(t)
	ctx := context.Background()
	const other = "99887766"
	if _, _, err := s.Enroll(ctx, devTestRx, devKey(t), nil, false, 0, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A different mailbox starts empty regardless of what any other has enrolled.
	if _, genesis, err := s.Enroll(ctx, other, devKey(t), nil, false, 0, false, nil, nil); err != nil || !genesis {
		t.Fatalf("genesis = %v, err = %v; a separate mailbox has its own registry", genesis, err)
	}
}

// TestDeviceMayVouch is the multiplication step, and the exemption that keeps the rule livable.
//
// The threat it answers: a device that reached a mailbox some way it should not have — an approval
// talked out of the owner, a borrowed unlocked screen — must not be able to enrol siblings the
// moment it arrives. Otherwise the owner who notices one hostile device and retires it is still
// shut out by the ones they never saw, and the only remedy left is a key rotation the attacker may
// well get to first.
func TestDeviceMayVouch(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	dev := func(name string, enrolledAgo time.Duration, opts ...func(*dmcnpb.DeviceRecord)) *dmcnpb.DeviceRecord {
		d := &dmcnpb.DeviceRecord{
			Ed25519PublicKey: []byte(name),
			EnrolledAt:       now.Add(-enrolledAgo).Unix(),
		}
		for _, o := range opts {
			o(d)
		}
		return d
	}
	retired := func(d *dmcnpb.DeviceRecord) { d.RetiredAt = now.Add(-time.Hour).Unix() }
	pending := func(d *dmcnpb.DeviceRecord) { d.EligibleAt = now.Add(time.Hour).Unix() }

	t.Run("the only device may vouch whatever its age", func(t *testing.T) {
		// The account adding its second device. A blanket probation would leave a new user unable
		// to pair a phone for a day and push them onto the recovery path, which is slower and
		// weaker — so this exemption is doing real work, not smoothing a corner.
		only := dev("genesis", time.Minute)
		if !DeviceMayVouch(only, []*dmcnpb.DeviceRecord{only}, now) {
			t.Fatal("a mailbox's only device could not add a second")
		}
	})

	t.Run("a device added minutes ago may not vouch beside an established one", func(t *testing.T) {
		old := dev("laptop", 90*24*time.Hour)
		fresh := dev("intruder", time.Minute)
		all := []*dmcnpb.DeviceRecord{old, fresh}
		if DeviceMayVouch(fresh, all, now) {
			t.Fatal("a device enrolled a minute ago vouched for another")
		}
		if !DeviceMayVouch(old, all, now) {
			t.Fatal("an established device was refused")
		}
	})

	t.Run("probation ends", func(t *testing.T) {
		old := dev("laptop", 90*24*time.Hour)
		grown := dev("phone", DeviceApprovalProbation+time.Minute)
		if !DeviceMayVouch(grown, []*dmcnpb.DeviceRecord{old, grown}, now) {
			t.Fatal("a device past its probation still could not vouch")
		}
	})

	t.Run("retired and pending devices never vouch", func(t *testing.T) {
		old := dev("laptop", 90*24*time.Hour)
		gone := dev("stolen", 90*24*time.Hour, retired)
		waiting := dev("recovered", 90*24*time.Hour, pending)
		all := []*dmcnpb.DeviceRecord{old, gone, waiting}
		if DeviceMayVouch(gone, all, now) {
			t.Fatal("a retired device vouched for another")
		}
		// A recovery enrolment inside its waiting period is on the mailbox and cannot act — which
		// includes vouching, or the delay would buy nothing.
		if DeviceMayVouch(waiting, all, now) {
			t.Fatal("a device still inside its recovery wait vouched for another")
		}
	})

	t.Run("the exemption counts ACTIVE devices, not entries", func(t *testing.T) {
		// A mailbox whose other devices are all retired is back to having one. Counting rows
		// instead would strand that owner: nothing left that may vouch, and no way to add one.
		alone := dev("survivor", time.Minute)
		all := []*dmcnpb.DeviceRecord{dev("old1", 90*24*time.Hour, retired), alone}
		if !DeviceMayVouch(alone, all, now) {
			t.Fatal("a mailbox with one active device could not add another")
		}
	})
}
