package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// The device registry operations (SPEC_EXT_DEVICES.md §4 to §6).
//
// Each has already passed AuthorizeMailbox, so the caller holds the account key. That is
// deliberately not enough to change the registry: a copied account key must not be able to
// introduce a device or remove the owner's.
//
// They return an *OpError where the refusal is one a client acts on. The stream handler and the
// in-process web backend both call these, so the two cannot drift apart.

// maxSealedDeviceLabel bounds the sealed name stored with a device. It is a name sealed to one
// key, a few hundred bytes. The relay keeps it indefinitely and cannot read it, so the cap is
// what stops a record carrying anything else.
const maxSealedDeviceLabel = 2048

var errNoDeviceRegistry = opError("UNSUPPORTED", "this relay does not keep a device registry")

// DeviceEnroll adds a device to a mailbox, and reports whether it created the registry.
//
// Which of the three ways in applies is decided from state the caller can't influence: the
// registry has never held a device, or an active device signed an approval over this exchange's
// nonce, or the caller asked for recovery and the domain allows it.
func (r *Relay) DeviceEnroll(ctx context.Context, rxHex, address string, op *dmcnpb.MailboxDeviceEnrollOp, nonce []byte) (*dmcnpb.DeviceRecord, bool, error) {
	if r.devices == nil {
		return nil, false, errNoDeviceRegistry
	}
	if len(op.GetEd25519PublicKey()) != ed25519.PublicKeySize {
		return nil, false, opError("INVALID_REQUEST", "device key must be 32 bytes")
	}
	if len(op.GetSealedLabel()) > maxSealedDeviceLabel {
		return nil, false, opError("INVALID_REQUEST", "the device name is too long")
	}
	if op.GetRecovery() && len(op.GetApproverEd25519PublicKey()) > 0 {
		return nil, false, opError("INVALID_REQUEST", "a recovery request cannot also carry an approval")
	}

	// The approval is verified here and not in the store: only this layer holds the nonce the
	// signature is bound to, and that binding is what makes an approval single-use.
	approved := false
	var attestedAt *time.Time
	if approver := op.GetApproverEd25519PublicKey(); len(approver) > 0 {
		approverRec, aerr := r.devices.Get(ctx, rxHex, approver)
		if aerr != nil || !DeviceActive(approverRec, r.devices.now()) {
			return nil, false, opError("AUTH_FAILED", "the approving device is not enrolled on this mailbox")
		}
		existing, lerr := r.devices.List(ctx, rxHex)
		if lerr != nil {
			return nil, false, opError("STORAGE_FAILED", "could not read the device registry")
		}
		// A device that arrived recently can't yet bring in others, so one wrongly admitted
		// device can't quietly enrol more before the owner notices it.
		if !DeviceMayVouch(approverRec, existing, r.devices.now()) {
			r.log.Warnf("device enrolment for %s refused: the approving device is too new", address)
			return nil, false, opError("DEVICE_ON_PROBATION",
				"the approving device is too new to approve another. Approve from a device that has been on this account longer")
		}
		at := time.Unix(op.GetApprovedAt(), 0).UTC()
		if err := identity.VerifyDeviceApproval(approver, address, op.GetEd25519PublicKey(), nonce, op.GetApproverSignature(), at); err != nil {
			r.log.Warnf("device enrolment for %s carried an approval that does not verify", address)
			return nil, false, opError("AUTH_FAILED", "the approval signature does not verify")
		}
		// The date the approver names becomes the new device's enrolment date, so it is bounded:
		// a device can't vouch for a moment it wasn't there for.
		if reason, ok := boundApprovedAt(op.GetApprovedAt(), approverRec, r.devices.now()); !ok {
			r.log.Warnf("device enrolment for %s attested an unusable date: %s", address, reason)
			return nil, false, opError("INVALID_REQUEST", reason)
		}
		attestedAt = &at
		approved = true
	}

	// The recovery delay is the domain's policy, read from its authority record, and only when
	// recovery was asked for. A relay that can't read the record refuses recovery: admitting an
	// unapproved device on a guess is the one outcome worth avoiding.
	recoveryDelay, recoveryAllowed := time.Duration(0), false
	if r.records != nil && op.GetRecovery() {
		if dar, derr := r.records.GetDAR(ctx, domainverify.DomainOf(address)); derr == nil && dar != nil {
			recoveryDelay, recoveryAllowed = dar.DeviceRecoveryDelay()
		}
	}

	enrolled, cerr := r.verifyDeviceCredential(ctx, address, op.GetEd25519PublicKey(), op.GetDeviceCredential())
	if cerr != nil {
		r.log.Warnf("device enrolment for %s carried a credential that does not verify: %v", address, cerr)
		return nil, false, opError("INVALID_REQUEST", "the device credential does not verify")
	}
	// An approval and a credential describe the same event, so they have to agree on when it
	// happened.
	if attestedAt != nil && enrolled != nil && absSeconds(enrolled.IssuedAt, *attestedAt) > int64(credentialFutureSkew/time.Second) {
		return nil, false, opError("INVALID_REQUEST",
			"the device credential and the approval disagree about when this device joined")
	}

	rec, genesis, err := r.devices.Enroll(ctx, rxHex, op.GetEd25519PublicKey(), op.GetSealedLabel(), approved, recoveryDelay, recoveryAllowed, enrolled, attestedAt)
	switch {
	case errors.Is(err, ErrDeviceExists):
		// A code of its own, because a client reads this answer as success.
		return nil, false, opError("DEVICE_ALREADY_ENROLLED", "this device is already enrolled")
	case errors.Is(err, ErrDeviceRetired):
		// The same code as a claimed registry, because the remedy is the same. Letting the old
		// key back in would undo the owner's removal. Pairing makes a new key.
		return nil, false, opError("DEVICE_APPROVAL_REQUIRED", ErrDeviceApprovalRequired.Error())
	case errors.Is(err, ErrDeviceRegistryClaimed) && op.GetRecovery():
		return nil, false, opError("DEVICE_RECOVERY_DISABLED", ErrDeviceRecoveryDisabled.Error())
	case errors.Is(err, ErrDeviceRegistryClaimed):
		return nil, false, opError("DEVICE_APPROVAL_REQUIRED", ErrDeviceApprovalRequired.Error())
	case err != nil:
		r.log.Errorf("device enrolment failed for %s: %v", address, err)
		return nil, false, opError("STORAGE_FAILED", "device enrolment failed")
	}

	switch {
	case genesis:
		r.log.Infof("%s enrolled its first device", address)
	case rec.EligibleAt != 0:
		// A warning: nobody vouched for this device. It is an owner who lost everything or a
		// copied key, and the two look the same from here.
		r.log.Warnf("%s admitted an unapproved device through recovery. It can act from %s unless a device on the mailbox removes it first",
			address, time.Unix(rec.EligibleAt, 0).UTC().Format(time.RFC3339))
	default:
		r.log.Successf("%s enrolled a device, approved by one already on the mailbox", address)
	}
	return rec, genesis, nil
}

// DeviceList returns every device on a mailbox, removed and waiting ones included. A removal is
// what an owner needs to be able to see.
func (r *Relay) DeviceList(ctx context.Context, rxHex, address string) ([]*dmcnpb.DeviceRecord, error) {
	if r.devices == nil {
		return nil, errNoDeviceRegistry
	}
	devices, err := r.devices.List(ctx, rxHex)
	if err != nil {
		r.log.Errorf("device list failed for %s: %v", address, err)
		return nil, opError("STORAGE_FAILED", "device list failed")
	}
	return devices, nil
}

// DeviceRetire removes a device. A different active device has to ask: the account key alone
// would let whoever copied it remove the owner's devices, and a device that could retire itself
// would let a registry be emptied one device at a time.
func (r *Relay) DeviceRetire(ctx context.Context, rxHex, address string, op *dmcnpb.MailboxDeviceRetireOp, nonce []byte) (*dmcnpb.DeviceRecord, error) {
	if r.devices == nil {
		return nil, errNoDeviceRegistry
	}
	target, signer := op.GetEd25519PublicKey(), op.GetSignerEd25519PublicKey()
	if len(target) != ed25519.PublicKeySize || len(signer) != ed25519.PublicKeySize {
		return nil, opError("INVALID_REQUEST", "device keys must be 32 bytes")
	}
	if bytes.Equal(target, signer) {
		return nil, opError("INVALID_REQUEST", "a device cannot remove itself. Ask from another device you still have")
	}
	if !r.devices.IsActive(ctx, rxHex, signer) {
		return nil, opError("AUTH_FAILED", "the requesting device is not enrolled on this mailbox")
	}
	if err := identity.VerifyDeviceRetirement(signer, address, target, nonce, op.GetSignerSignature()); err != nil {
		r.log.Warnf("device retirement for %s carried a signature that does not verify", address)
		return nil, opError("AUTH_FAILED", "the retirement signature does not verify")
	}
	rec, err := r.devices.Retire(ctx, rxHex, target)
	switch {
	case errors.Is(err, ErrDeviceUnknown):
		return nil, opError("INVALID_REQUEST", "no such device on this mailbox")
	case errors.Is(err, ErrDeviceLastActive):
		return nil, opError("INVALID_REQUEST", "this is the only device still enrolled. Add its replacement first, then remove it")
	case err != nil:
		r.log.Errorf("device retirement failed for %s: %v", address, err)
		return nil, opError("STORAGE_FAILED", "device retirement failed")
	}
	r.log.Infof("%s retired a device", address)
	return rec, nil
}

// Devices is the relay's device registry, or nil where it keeps none.
func (r *Relay) Devices() *DeviceStore { return r.devices }

// WithDeviceRegistry gives the relay a device registry. From then on a mailbox is gated on its
// devices from its first enrolment (AuthorizeMailbox), and the relay advertises the capability.
func WithDeviceRegistry(store *DeviceStore) Option {
	return func(o *relayOptions) {
		o.devices = store
	}
}

// verifyDeviceCredential checks the domain's attestation of a device, returning nil when none was
// supplied — enrolment without one is legitimate and simply yields a device that can gate access
// but never authorize a key rotation.
//
// Everything here is a binding: the credential must be for THIS device, THIS address and the
// device role, and must chain to the domain that owns the address. Without the first three a
// credential minted for one device or one account would be spendable on another; without the
// last it would be a self-signed claim.
func (r *Relay) verifyDeviceCredential(ctx context.Context, address string, devicePub, marshaled []byte) (*EnrolledCredential, error) {
	if len(marshaled) == 0 {
		return nil, nil
	}
	cred, err := identity.CredentialFromProtoBytes(marshaled)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if !cred.HasRole(identity.RoleDevice) {
		return nil, errors.New("not a device credential")
	}
	if !bytes.Equal(cred.Subject, devicePub) {
		return nil, errors.New("credential subject is a different device")
	}
	if !strings.EqualFold(cred.Address, address) {
		return nil, fmt.Errorf("credential is for %q, not %q", cred.Address, address)
	}
	// A forward-dated credential would enrol a device that is somehow already old, which is the
	// one direction tenure must never move. The domain signs the date, so this is hygiene rather
	// than a defence against the client — but a date nobody can act on yet has no honest use.
	if cred.IssuedAt.After(r.devices.now().Add(credentialFutureSkew)) {
		return nil, fmt.Errorf("credential is dated %s, in the future", cred.IssuedAt.UTC().Format(time.RFC3339))
	}
	if r.records == nil {
		return nil, errors.New("no domain authority held to verify it against")
	}
	dar, derr := r.records.GetDAR(ctx, domainverify.DomainOf(address))
	if derr != nil || dar == nil {
		return nil, fmt.Errorf("no domain authority for %s", domainverify.DomainOf(address))
	}
	if verr := identity.VerifyCredential(cred, dar, nil, r.devices.now()); verr != nil {
		return nil, verr
	}
	return &EnrolledCredential{IssuedAt: cred.IssuedAt, Marshaled: marshaled}, nil
}

// credentialFutureSkew tolerates ordinary clock drift between the issuer and this relay.
const credentialFutureSkew = 5 * time.Minute

// boundApprovedAt reports whether an approver may attest this moment as a device's enrolment.
//
// Three bounds, for three different reasons. The approval has to name a time AT ALL: it is taken
// from the wire in seconds, where an absent field and "the first second of 1970" are the same
// value, so it is judged there rather than as a time.Time — a converted one is never the zero
// time, and the check that looked for one could never fire, leaving a client that simply omitted
// the field to be told its approval predated the approver's enrolment. Then: not in the FUTURE,
// or a device would arrive already aged. And not before the APPROVER'S own enrolment, because a
// device cannot vouch for a moment it did not exist for — which is what stops tenure being
// manufactured by a young device approving a backdated one.
func boundApprovedAt(atUnix int64, approver *dmcnpb.DeviceRecord, now time.Time) (reason string, ok bool) {
	if atUnix <= 0 {
		return "the approval names no time", false
	}
	at := time.Unix(atUnix, 0).UTC()
	if at.After(now.Add(credentialFutureSkew)) {
		return "the approval is dated in the future", false
	}
	if at.Unix() < approver.EnrolledAt {
		return "the approval predates the approving device's own enrolment", false
	}
	return "", true
}

// absSeconds returns the absolute difference between two times, in seconds.
func absSeconds(a, b time.Time) int64 {
	d := a.Unix() - b.Unix()
	if d < 0 {
		return -d
	}
	return d
}

// ClientMailboxOp runs one mailbox op against another relay: it opens the challenge, hands the
// nonce to build, and sends what build returns. The nonce comes first because the device ops
// sign over it, and a device proof covers it too. build sets every proof field itself.
//
// A refusal comes back as an *OpError carrying the relay's code. Not for the body op, whose
// response streams (ClientMailboxBody).
func (r *Relay) ClientMailboxOp(ctx context.Context, peerID peer.ID, address string, build func(nonce []byte) (*dmcnpb.MailboxOp, error)) (*dmcnpb.RelayResponse, error) {
	nonce, s, err := r.ClientFetchChallenge(ctx, peerID, address)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	op, err := build(nonce)
	if err != nil {
		return nil, err
	}
	op.Nonce = nonce
	if err := writeRequest(s, &dmcnpb.RelayRequest{Request: &dmcnpb.RelayRequest_MailboxOp{MailboxOp: op}}); err != nil {
		return nil, fmt.Errorf("relay: mailbox op: write: %w", err)
	}
	resp, err := readResponse(s)
	if err != nil {
		return nil, fmt.Errorf("relay: mailbox op: read: %w", err)
	}
	if e := resp.GetError(); e != nil {
		return nil, &OpError{Code: e.Code, Message: e.Message}
	}
	return resp, nil
}
