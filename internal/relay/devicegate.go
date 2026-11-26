package relay

import (
	"context"
	"crypto/ed25519"
	"strings"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// The mailbox gate (SPEC_EXT_DEVICES.md §3).
//
// The account signature says whose mailbox this is. A device signature says the request comes
// from somewhere the owner approved. Once a mailbox has held a device, every request needs the
// second, and which requests also need the first depends on what they do.

// OpClass is how much proof an operation needs on a mailbox that has devices.
type OpClass int

const (
	// ClassOwner needs the account signature and an active device's. The default: anything not
	// named as ClassDevice is this.
	ClassOwner OpClass = iota
	// ClassDevice needs an active device's signature and nothing else. These read the mailbox,
	// or change state the owner can change back.
	ClassDevice
	// ClassEnroll needs the account signature and is exempt from the device rule: the first
	// device has no device to sign for it, and a newcomer being approved isn't on the list yet.
	// The enrolment itself decides whether the device may join.
	ClassEnroll
)

// MailboxProof is what a mailbox request brings to the gate.
type MailboxProof struct {
	Nonce           []byte
	Signature       []byte // the account key, over Nonce; may be empty on a ClassDevice op
	DevicePublic    []byte
	DeviceSignature []byte // the device key, over identity.DeviceChallengeBytes(Nonce)
}

// OpError is a refusal a client acts on by its code, never by its words.
type OpError struct {
	Code    string
	Message string
}

func (e *OpError) Error() string { return e.Message }

func opError(code, msg string) *OpError { return &OpError{Code: code, Message: msg} }

// The names a device may write on its own. They are protocol: a relay matches them byte for
// byte, with no case folding. "settings/labels" is one key and not a prefix, so every other key
// under "settings/" stays with the owner.
var (
	deviceWritablePrefixes  = []string{"drafts/", "draft-body/", "draft-att/", "flags/"}
	deviceWritableKeys      = []string{"settings/labels"}
	deviceDeletablePrefixes = []string{"drafts/", "draft-body/", "draft-att/"}
)

// KvPutClass is the class of a write to `key`.
func KvPutClass(key string) OpClass {
	for _, k := range deviceWritableKeys {
		if key == k {
			return ClassDevice
		}
	}
	return classByPrefix(key, deviceWritablePrefixes)
}

// KvDeleteClass is the class of a delete of `key`. Narrower than a write: a flag record can be
// rewritten by a device and removed only by the owner.
func KvDeleteClass(key string) OpClass {
	return classByPrefix(key, deviceDeletablePrefixes)
}

func classByPrefix(key string, prefixes []string) OpClass {
	for _, p := range prefixes {
		// A bare prefix names no entry, so it gets no special standing.
		if len(key) > len(p) && strings.HasPrefix(key, p) {
			return ClassDevice
		}
	}
	return ClassOwner
}

// deviceChallengeNonceSize is the length of every challenge this relay issues. No device action
// fits in 32 bytes, so a proof over anything else is answering a different question.
const deviceChallengeNonceSize = 32

// AuthorizeMailbox decides whether a request on rec's mailbox may proceed, and reports which
// active device signed it (nil where none did). Every path to a mailbox goes through here.
//
// In order:
//
//  1. An account signature that is present has to verify. A bad one is never ignored.
//  2. A mailbox that has never held a device is answered on the account signature alone.
//  3. Otherwise the request needs a proof from an active device. That includes a mailbox whose
//     devices have all been removed: the registry is still claimed, or removing devices would
//     reopen the mailbox to a copied account key.
//  4. A ClassOwner operation needs the account signature as well.
//
// A registry that cannot be read refuses a request that brought no valid device proof.
func (r *Relay) AuthorizeMailbox(ctx context.Context, rec *identity.IdentityRecord, proof MailboxProof, class OpClass) (device []byte, err error) {
	signed := len(proof.Signature) > 0
	if signed && crypto.Verify(rec.Ed25519Public, proof.Nonce, proof.Signature) != nil {
		return nil, opError("AUTH_FAILED", ErrAuthFailed.Error())
	}
	if r.devices == nil {
		// No registry here, so the account key is the only proof there is.
		if !signed {
			return nil, opError("AUTH_FAILED", ErrAuthFailed.Error())
		}
		return nil, nil
	}
	rxHex := mailboxKeyHex(rec)

	hasProof := len(proof.DevicePublic) == ed25519.PublicKeySize && len(proof.DeviceSignature) > 0
	if hasProof && r.devices.IsActive(ctx, rxHex, proof.DevicePublic) {
		if len(proof.Nonce) != deviceChallengeNonceSize ||
			identity.VerifyDeviceChallenge(proof.DevicePublic, proof.Nonce, proof.DeviceSignature) != nil {
			return nil, opError("AUTH_FAILED", "the device proof does not verify")
		}
		if !signed && class != ClassDevice {
			return nil, opError("AUTH_FAILED", "this operation needs the account's signature as well as the device's")
		}
		return proof.DevicePublic, nil
	}

	// No proof from an active device. Everything from here needs the account key.
	if !signed {
		return nil, opError("AUTH_FAILED", ErrAuthFailed.Error())
	}
	if class == ClassEnroll {
		return nil, nil
	}
	held, lerr := r.devices.List(ctx, rxHex)
	if lerr != nil {
		r.log.Errorf("device registry unreadable for %s: %v", rec.Address, lerr)
		return nil, opError("STORAGE_FAILED", "the device registry is unavailable")
	}
	if len(held) == 0 {
		return nil, nil // never held a device: nothing to check against
	}
	// One answer for a device that was never enrolled, one that was removed, and one still
	// inside its recovery wait. Which it was is something the owner knows already.
	return nil, opError("DEVICE_NOT_ENROLLED", ErrDeviceNotEnrolled.Error())
}

// AuthorizeSend is the gate for a send made on a client's behalf (§9): the same rules over a
// send proof, which is the device's signature on the envelope hash the sender's STORE signature
// covers. The caller has verified that STORE signature.
func (r *Relay) AuthorizeSend(ctx context.Context, rec *identity.IdentityRecord, envHash, devicePub, deviceSig []byte) error {
	if r.devices == nil {
		return nil
	}
	rxHex := mailboxKeyHex(rec)
	if len(devicePub) == ed25519.PublicKeySize && len(deviceSig) > 0 && r.devices.IsActive(ctx, rxHex, devicePub) {
		if identity.VerifyDeviceSend(devicePub, envHash, deviceSig) != nil {
			return opError("AUTH_FAILED", "the device proof does not verify")
		}
		return nil
	}
	held, err := r.devices.List(ctx, rxHex)
	if err != nil {
		r.log.Errorf("device registry unreadable for %s: %v", rec.Address, err)
		return opError("STORAGE_FAILED", "the device registry is unavailable")
	}
	if len(held) == 0 {
		return nil
	}
	return opError("DEVICE_NOT_ENROLLED", ErrDeviceNotEnrolled.Error())
}

// mailboxKeyHex is the key every mailbox store uses: the hex of the owner's X25519 public key.
func mailboxKeyHex(rec *identity.IdentityRecord) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range rec.X25519Public {
		out = append(out, digits[b>>4], digits[b&0x0f])
	}
	return string(out)
}
