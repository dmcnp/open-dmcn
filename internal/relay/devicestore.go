package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	ds "github.com/ipfs/go-datastore"
	dsq "github.com/ipfs/go-datastore/query"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// devicePrefix namespaces a mailbox's enrolled devices, keyed by the mailbox key (rxHex) and
// then by the device's own public key — so listing one mailbox's devices is a prefix scan and
// enrolling one is a single write, with no read-modify-write over a combined blob.
const devicePrefix = "/dmcn/devices"

var (
	// ErrDeviceExists: this device is already enrolled here.
	ErrDeviceExists = errors.New("relay: device already enrolled")
	// ErrDeviceRetired: this device key was on the mailbox and has been removed. A removed key
	// never comes back: the device pairs again under a FRESH key, so the tombstone of the old
	// one stays exactly where the owner left it.
	ErrDeviceRetired = errors.New("relay: device was removed from this mailbox")
	// ErrDeviceUnknown: no such device on this mailbox.
	ErrDeviceUnknown = errors.New("relay: device not enrolled")
	// ErrDeviceRegistryClaimed: the registry already has devices, so this enrolment needed an
	// approval from one of them and did not carry a valid one.
	ErrDeviceRegistryClaimed = errors.New("relay: device registry already claimed — enrolment needs approval from an enrolled device")
	// ErrDeviceLastActive: this device is the only one still enrolled, and a mailbox must never
	// be left with none. A registry with no active devices can approve no newcomer, so the
	// account would be reachable by nobody — and reopening enrolment to whoever holds the
	// account key, which is the only other way out, is exactly what the registry exists to
	// prevent. Getting back in after losing every device is the recovery path's job.
	ErrDeviceLastActive = errors.New("relay: cannot retire the only enrolled device")
	// ErrDeviceSelfRetire: a device asked to retire itself. Refused so the registry can never be
	// walked down to empty one device at a time, each retiring itself in turn.
	ErrDeviceSelfRetire = errors.New("relay: a device cannot retire itself")
	// ErrDeviceApprovalRequired is the CLIENT-side view of ErrDeviceRegistryClaimed: the request
	// authenticated, and what it lacks is an approval from a device already on the mailbox.
	// Distinct from an auth failure because the remedy is unrelated — confirm from a device you
	// already have, rather than fix your credentials.
	ErrDeviceApprovalRequired = errors.New("relay: enrolment needs approval from a device already on this mailbox")
	// ErrDeviceNotEnrolled: the request proved the account key but brought no valid proof from a
	// device this mailbox has enrolled. Holding the account key is half the answer; the other
	// half is being somewhere the owner approved.
	ErrDeviceNotEnrolled = errors.New("relay: this mailbox requires a proof from an enrolled device")
	// ErrDeviceRecoveryDisabled: a recovery request on a domain that has turned recovery off. Kept
	// apart from ErrDeviceApprovalRequired because the browser has to tell the two answers to a
	// recovery request apart: "this domain does not allow it" and "this browser was removed".
	ErrDeviceRecoveryDisabled = errors.New("relay: this domain does not let a device join without approval")
)

// DeviceStore records which devices a mailbox has enrolled, and when.
//
// The relay holds this because it is the one party that can say when it FIRST SAW a device.
// An owner cannot backdate an enrolment and a thief cannot mint an old one, which is what makes
// a tenure rule mean anything. It learns a device's public key and that date, and nothing
// else — labels arrive sealed to the owner.
type DeviceStore struct {
	store ds.Batching
	// mu serializes the read-modify-write in Enroll. The genesis rule is "accept iff the
	// registry is empty", and two devices racing on an empty registry would otherwise both
	// read empty and both claim it.
	mu sync.Mutex
	// now is the clock, overridable in tests. Enrolment dates are the relay's own
	// observation, so nothing else may set them.
	now func() time.Time
}

// NewDeviceStore returns a device store over the given (borrowed) datastore.
func NewDeviceStore(d ds.Batching) *DeviceStore {
	return &DeviceStore{store: d, now: time.Now}
}

// SetClock overrides the enrolment clock. Tests only.
func (s *DeviceStore) SetClock(now func() time.Time) { s.now = now }

func deviceKey(rxHex string, devicePub []byte) ds.Key {
	return ds.NewKey(fmt.Sprintf("%s/%s/%s", devicePrefix, rxHex, hex.EncodeToString(devicePub)))
}

func deviceMailboxPrefix(rxHex string) string {
	return fmt.Sprintf("%s/%s", devicePrefix, rxHex)
}

// List returns every device on this mailbox, tombstones included, oldest enrolment first.
//
// Retired devices are returned rather than hidden: a device removed by someone who held the
// account key must leave a trace the owner can see, which a silent delete would not.
func (s *DeviceStore) List(ctx context.Context, rxHex string) ([]*dmcnpb.DeviceRecord, error) {
	res, err := s.store.Query(ctx, dsq.Query{Prefix: deviceMailboxPrefix(rxHex)})
	if err != nil {
		return nil, err
	}
	defer res.Close()

	var out []*dmcnpb.DeviceRecord
	for entry := range res.Next() {
		if entry.Error != nil {
			return nil, entry.Error
		}
		var rec dmcnpb.DeviceRecord
		if err := proto.Unmarshal(entry.Value, &rec); err != nil {
			return nil, fmt.Errorf("relay: device record unmarshal: %w", err)
		}
		out = append(out, &rec)
	}
	// Deterministic order across replicas: oldest enrolment first, and the device key breaks a
	// tie. Two nodes listing the same registry must agree on which device is the eldest, since
	// that is what a tenure rule reads.
	sort.Slice(out, func(i, j int) bool {
		if out[i].EnrolledAt != out[j].EnrolledAt {
			return out[i].EnrolledAt < out[j].EnrolledAt
		}
		return hex.EncodeToString(out[i].Ed25519PublicKey) < hex.EncodeToString(out[j].Ed25519PublicKey)
	})
	return out, nil
}

// DeviceApprovalProbation is how long a device must have been on a mailbox before it may vouch
// for ANOTHER device.
//
// It closes the multiplication step. A device that reaches a mailbox some way it should not have
// — an approval talked out of the owner, a moment with an unlocked screen — can read mail, and
// that is bad enough; what it must not also do is instantly enrol siblings, so that the owner who
// spots one and retires it is still shut out by the ones they did not see. The probation turns
// "instant redundancy" into "redundancy tomorrow, if nobody looked", which is the same trade the
// recovery delay makes.
//
// It buys no tenure either way: boundApprovedAt already caps an approval's attested date at the
// approver's own enrolment, so a chain of approvals can never be older than its youngest link and
// a key rotation stays as far away as it was.
//
// A day rather than the rotation minimum, because this rule is met by ordinary people setting up
// ordinary devices. The genesis exemption below is what keeps that true on day one.
const DeviceApprovalProbation = 24 * time.Hour

// DeviceMayVouch reports whether `approver` may approve another device onto this mailbox now,
// given every device the mailbox already holds.
//
// The exemption is what makes the rule livable: a device that is the mailbox's ONLY active one
// may vouch immediately, whatever its age. That is exactly the account whose first device is
// adding the second — the case a blanket probation would break, leaving a new user unable to pair
// a phone for a day and pushing them onto the recovery path, which is slower and weaker. It also
// covers the owner who recovered into a single new device, which has already waited out the
// recovery delay to get there.
func DeviceMayVouch(approver *dmcnpb.DeviceRecord, all []*dmcnpb.DeviceRecord, now time.Time) bool {
	if !DeviceActive(approver, now) {
		return false
	}
	active := 0
	for _, d := range all {
		if DeviceActive(d, now) {
			active++
		}
	}
	if active <= 1 {
		return true
	}
	return now.Sub(time.Unix(approver.EnrolledAt, 0)) >= DeviceApprovalProbation
}

// DevicePending reports whether a record is a recovery enrolment still inside its waiting
// period: admitted, visible, and not yet able to act.
func DevicePending(d *dmcnpb.DeviceRecord, now time.Time) bool {
	return d.RetiredAt == 0 && d.EligibleAt != 0 && now.Unix() < d.EligibleAt
}

// DeviceActive reports whether a record may act on the mailbox now — enrolled, not retired, and
// past any recovery wait.
func DeviceActive(d *dmcnpb.DeviceRecord, now time.Time) bool {
	return d.RetiredAt == 0 && !DevicePending(d, now)
}

// Active returns the devices that may act on this mailbox right now.
//
// A recovery enrolment still inside its waiting period is deliberately NOT here: it is on the
// mailbox, it is visible, and it cannot do anything yet. That distinction is the whole of the
// recovery design — the request is admitted slowly and in the open rather than refused, so the
// owner has the window to notice and veto it.
func (s *DeviceStore) Active(ctx context.Context, rxHex string) ([]*dmcnpb.DeviceRecord, error) {
	all, err := s.List(ctx, rxHex)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]*dmcnpb.DeviceRecord, 0, len(all))
	for _, d := range all {
		if DeviceActive(d, now) {
			out = append(out, d)
		}
	}
	return out, nil
}

// Pending returns the recovery enrolments still waiting out their delay.
func (s *DeviceStore) Pending(ctx context.Context, rxHex string) ([]*dmcnpb.DeviceRecord, error) {
	all, err := s.List(ctx, rxHex)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]*dmcnpb.DeviceRecord, 0, len(all))
	for _, d := range all {
		if DevicePending(d, now) {
			out = append(out, d)
		}
	}
	return out, nil
}

// Get returns one device record, or ErrDeviceUnknown.
func (s *DeviceStore) Get(ctx context.Context, rxHex string, devicePub []byte) (*dmcnpb.DeviceRecord, error) {
	data, err := s.store.Get(ctx, deviceKey(rxHex, devicePub))
	if errors.Is(err, ds.ErrNotFound) {
		return nil, ErrDeviceUnknown
	}
	if err != nil {
		return nil, err
	}
	var rec dmcnpb.DeviceRecord
	if err := proto.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("relay: device record unmarshal: %w", err)
	}
	return &rec, nil
}

// IsActive reports whether this device is enrolled and not retired.
func (s *DeviceStore) IsActive(ctx context.Context, rxHex string, devicePub []byte) bool {
	rec, err := s.Get(ctx, rxHex, devicePub)
	return err == nil && DeviceActive(rec, s.now())
}

// Enroll adds a device, returning the stored record and whether it created the registry.
//
// `approved` reports that an already-enrolled device vouched for this one; the caller verifies
// that signature, because only it holds the challenge nonce the approval is bound to. Enrolment
// is permitted when the registry has NEVER held a device (genesis) or when `approved` — and
// refused otherwise, which is the rule that keeps a stolen account key from introducing one.
func (s *DeviceStore) Enroll(ctx context.Context, rxHex string, devicePub []byte, sealedLabel []byte, approved bool, recoveryDelay time.Duration, recoveryAllowed bool, cred *EnrolledCredential, attestedAt *time.Time) (rec *dmcnpb.DeviceRecord, genesis bool, err error) {
	if len(devicePub) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("relay: device key is %d bytes, want %d", len(devicePub), ed25519.PublicKeySize)
	}
	// Serialize the whole check-then-write. Without this two devices racing on an empty
	// registry both read empty and both claim genesis, and the mailbox ends up with two
	// "first" devices that never approved each other.
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, gerr := s.Get(ctx, rxHex, devicePub); gerr == nil {
		// Told apart from "already enrolled" because the browser reads that answer as success:
		// a removed device probing its way back in would otherwise believe it was fine until its
		// first mailbox call failed with nothing to explain why.
		if existing.RetiredAt != 0 {
			return nil, false, ErrDeviceRetired
		}
		return nil, false, ErrDeviceExists
	} else if !errors.Is(gerr, ErrDeviceUnknown) {
		return nil, false, gerr
	}

	// Genesis means the registry has NEVER held a device, which is why this reads List rather
	// than Active. A tombstone keeps it claimed: if retiring every device reopened the genesis
	// path, an owner who lost their only phone — or an attacker who retired theirs — would hand
	// the mailbox to whoever next presented the account key. Once claimed, always claimed;
	// getting back in after losing every device is the recovery path's job, not this one's.
	known, err := s.List(ctx, rxHex)
	if err != nil {
		return nil, false, err
	}
	genesis = len(known) == 0

	rec = &dmcnpb.DeviceRecord{
		Ed25519PublicKey: devicePub,
		EnrolledAt:       s.now().Unix(),
		SealedLabel:      sealedLabel,
	}
	// Where the domain has attested this device, its issued_at becomes the enrolment date rather
	// than this relay's clock. That is the join between two numbers that would otherwise drift:
	// the date a key rotation is judged against — checked by every node in the fleet, which has
	// only the credential to go on — and the date this relay gates access on. Taking the signed
	// one for both makes them the same by construction, and a client cannot move it because a
	// client cannot sign it.
	// The enrolment date comes from whichever SIGNED attestation exists, and the relay's own
	// clock is only the last resort:
	//
	//  1. the approving device's attested time, where one approved this enrolment — the natural
	//     source, since the approval IS the moment of joining and a device already trusted here
	//     signed for it;
	//  2. the credential's issued_at, for a genesis or recovery enrolment where no device was
	//     there to approve;
	//  3. this node's clock, when neither exists.
	//
	// The caller has already checked that any two of these agree, so the order matters only for
	// which is present.
	if attestedAt != nil {
		rec.EnrolledAt = attestedAt.Unix()
	} else if cred != nil {
		rec.EnrolledAt = cred.IssuedAt.Unix()
	}
	if cred != nil {
		rec.DeviceCredential = cred.Marshaled
	}
	switch {
	case genesis || approved:
		// Effective immediately: either the registry was empty, or a device already on the
		// mailbox vouched for this one.
	case !recoveryAllowed:
		return nil, false, ErrDeviceRegistryClaimed
	default:
		// RECOVERY. Nobody vouched for this device, so it joins on a delay instead of being
		// refused — the path an owner takes when every device they had is gone. It is visible on
		// the mailbox for the whole wait, and any device that IS active may veto it by retiring
		// it. Where no active device remains, nobody vetoes and the owner gets back in, which is
		// the case the whole arm exists for.
		rec.EligibleAt = s.now().Add(recoveryDelay).Unix()
	}
	data, err := proto.Marshal(rec)
	if err != nil {
		return nil, false, fmt.Errorf("relay: device record marshal: %w", err)
	}
	if err := s.store.Put(ctx, deviceKey(rxHex, devicePub), data); err != nil {
		return nil, false, err
	}
	return rec, genesis, nil
}

// EnrolledCredential is a device credential the caller has ALREADY verified — chained to the
// domain, subject matching the device, role and address checked.
//
// It is a distinct type rather than a raw Credential so that reaching the store means the
// verification happened: the store records the issued_at as a fact about the mailbox, and a
// caller handing over something unverified would be writing a date nobody vouched for.
type EnrolledCredential struct {
	IssuedAt  time.Time
	Marshaled []byte
}

// Retire tombstones a device. It is idempotent: retiring an already-retired device returns the
// existing record rather than moving its date, so a second attempt cannot rewrite when the
// device actually lost access.
func (s *DeviceStore) Retire(ctx context.Context, rxHex string, devicePub []byte) (*dmcnpb.DeviceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, err := s.Get(ctx, rxHex, devicePub)
	if err != nil {
		return nil, err
	}
	if rec.RetiredAt != 0 {
		return rec, nil
	}
	// Never leave a mailbox with no ACTIVE device. The handler already refuses a device retiring
	// ITSELF, which makes this unreachable through that path — but the invariant is what the
	// registry's safety rests on, so it is enforced where the state actually changes rather than
	// only where today's one caller happens to check.
	//
	// Retiring a PENDING device is the veto, and it can never breach the invariant because a
	// pending device was not part of the active set to begin with. Guarding it anyway would make
	// the veto impossible on exactly the mailbox that needs it most: the one with no active
	// device left, which is where a hostile recovery request is least likely to be noticed.
	if DeviceActive(rec, s.now()) {
		active, aerr := s.Active(ctx, rxHex)
		if aerr != nil {
			return nil, aerr
		}
		if len(active) <= 1 {
			return nil, ErrDeviceLastActive
		}
	}
	rec.RetiredAt = s.now().Unix()
	data, err := proto.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("relay: device record marshal: %w", err)
	}
	if err := s.store.Put(ctx, deviceKey(rxHex, devicePub), data); err != nil {
		return nil, err
	}
	return rec, nil
}
