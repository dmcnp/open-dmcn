package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/domainverify"
)

// What a device key signs (SPEC_EXT_DEVICES.md §7). Each signature has a tag of its own, so one
// can never be presented as another: an approval lets a device in and a retirement cuts one off,
// and a shared tag would make each usable as the other.
const (
	ctxDeviceApproval   = "dmcn-device-approve-v1\x00"
	ctxDeviceRetirement = "dmcn-device-retire-v1\x00"
	ctxDeviceChallenge  = "dmcn-device-challenge-v1\x00"
	ctxDeviceSend       = "dmcn-device-send-v1\x00"
)

// deviceActionBytes builds what an enrolled device signs to act on another device.
//
// Each part closes a replay: the address, so an approval on one mailbox is worth nothing on
// another; the subject key, so vouching for one device is not vouching for any other; the live
// nonce, so a signature captured from an earlier exchange can't be spent again; and the time
// the signer attests, where there is one.
//
// A zero `at` adds nothing to the bytes.
func deviceActionBytes(ctx, address string, subjectPub, nonce []byte, at time.Time) []byte {
	lower := strings.ToLower(address)
	buf := make([]byte, 0, len(ctx)+len(lower)+len(subjectPub)+len(nonce)+8)
	buf = append(buf, ctx...)
	buf = append(buf, lower...)
	buf = append(buf, subjectPub...)
	buf = append(buf, nonce...)
	if !at.IsZero() {
		buf = binary.BigEndian.AppendUint64(buf, uint64(at.Unix()))
	}
	return buf
}

// NewDeviceCredential builds a domain's attestation of one device: role "device", the device's
// own key as subject, issued when the device joined.
//
// It says the domain saw this key on this address at this time. It does not say the device is
// allowed on the mailbox: that is the registry's decision. Its use is to a node that holds no
// registry and has to judge how long a device has been enrolled (SPEC_EXT_ROTATION.md §3).
//
// It has no expiry. It records when something happened, and an expired one would make a
// device's history unverifiable.
func NewDeviceCredential(devicePub ed25519.PublicKey, address string, at time.Time) *Credential {
	return &Credential{
		Version:  1,
		Subject:  devicePub,
		Domain:   domainverify.DomainOf(address),
		Address:  address,
		Roles:    []string{RoleDevice},
		IssuedAt: at.UTC(),
	}
}

// SignDeviceApproval signs an enrolled device's approval of `subjectPub` joining `address` at
// `at`. The time is the approver's to state and becomes the new device's enrolment date; a
// relay bounds it (never in the future, never before the approver's own enrolment).
func SignDeviceApproval(priv ed25519.PrivateKey, address string, subjectPub, nonce []byte, at time.Time) ([]byte, error) {
	return crypto.Sign(priv, deviceActionBytes(ctxDeviceApproval, address, subjectPub, nonce, at))
}

// VerifyDeviceApproval checks an approval, over the time it attested.
func VerifyDeviceApproval(approverPub ed25519.PublicKey, address string, subjectPub, nonce, sig []byte, at time.Time) error {
	return crypto.Verify(approverPub, deviceActionBytes(ctxDeviceApproval, address, subjectPub, nonce, at), sig)
}

// SignDeviceRetirement signs an enrolled device's request to remove `subjectPub`. It carries no
// time: the date a device lost access feeds no later decision.
func SignDeviceRetirement(priv ed25519.PrivateKey, address string, subjectPub, nonce []byte) ([]byte, error) {
	return crypto.Sign(priv, deviceActionBytes(ctxDeviceRetirement, address, subjectPub, nonce, time.Time{}))
}

// VerifyDeviceRetirement checks a retirement signature.
func VerifyDeviceRetirement(signerPub ed25519.PublicKey, address string, subjectPub, nonce, sig []byte) error {
	return crypto.Verify(signerPub, deviceActionBytes(ctxDeviceRetirement, address, subjectPub, nonce, time.Time{}), sig)
}

// DeviceChallengeBytes is what a device signs to answer a relay's challenge.
//
// The tag matters most here. The relay picks the nonce and a device signs what it is handed, so
// without the tag a hostile relay could serve the bytes of an approval as a challenge and
// collect a signature that enrols its own device somewhere else.
func DeviceChallengeBytes(nonce []byte) []byte {
	buf := make([]byte, 0, len(ctxDeviceChallenge)+len(nonce))
	buf = append(buf, ctxDeviceChallenge...)
	return append(buf, nonce...)
}

// SignDeviceChallenge answers a relay's challenge with this device's key.
func SignDeviceChallenge(priv ed25519.PrivateKey, nonce []byte) ([]byte, error) {
	return crypto.Sign(priv, DeviceChallengeBytes(nonce))
}

// VerifyDeviceChallenge checks a device's answer to a challenge.
func VerifyDeviceChallenge(devicePub ed25519.PublicKey, nonce, sig []byte) error {
	return crypto.Verify(devicePub, DeviceChallengeBytes(nonce), sig)
}

// DeviceSendBytes is what a device signs to send one message through a service that sends on
// its behalf: a tag and the envelope hash the sender's STORE signature covers (§9). The hash is
// the sender's choice, unlike a challenge, so it has its own tag.
func DeviceSendBytes(envHash []byte) []byte {
	buf := make([]byte, 0, len(ctxDeviceSend)+len(envHash))
	buf = append(buf, ctxDeviceSend...)
	return append(buf, envHash...)
}

// SignDeviceSend signs a send proof with this device's key.
func SignDeviceSend(priv ed25519.PrivateKey, envHash []byte) ([]byte, error) {
	return crypto.Sign(priv, DeviceSendBytes(envHash))
}

// VerifyDeviceSend checks a device's send proof over envHash.
func VerifyDeviceSend(devicePub ed25519.PublicKey, envHash, sig []byte) error {
	return crypto.Verify(devicePub, DeviceSendBytes(envHash), sig)
}
