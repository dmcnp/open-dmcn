package identity

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// Known-answer vectors for the bytes an enrolled device signs to act on another device.
//
// The browser produces these (src/lib/crypto/deviceKey.ts) and the relay verifies them, so the
// two encoders must agree to the byte. The places they can drift are the ones nobody eyeballs:
// the context tag and its trailing NUL, lowercasing the address, the field order, and whether the
// attested time is present at all — an approval carries one, a retirement does not, and encoding
// a zero where the other side encodes nothing would break every signature silently.
//
// Fixed inputs: subject device key = 32x0x21, nonce = 32x0x22, attested at 1700000000, address
// given in MIXED CASE so the lowercasing is actually exercised.
const (
	vecDeviceApprove = "646d636e2d6465766963652d617070726f76652d763100766563746f72407061726974792e6578616d706c6521212121212121212121212121212121212121212121212121212121212121212222222222222222222222222222222222222222222222222222222222222222000000006553f100"
	vecDeviceRetire  = "646d636e2d6465766963652d7265746972652d763100766563746f72407061726974792e6578616d706c6521212121212121212121212121212121212121212121212121212121212121212222222222222222222222222222222222222222222222222222222222222222"
	// The challenge answer binds nothing but the nonce — there is nothing else to bind, since the
	// relay already knows which mailbox it asked about. What the tag buys is that these bytes can
	// never also be an approval or a retirement, whatever nonce a hostile node chooses.
	vecDeviceChallenge = "646d636e2d6465766963652d6368616c6c656e67652d7631002222222222222222222222222222222222222222222222222222222222222222"
	// The send proof: the tag and the envelope hash (here the same 32 bytes as the nonce), so a send
	// proof is never also a challenge answer and the reverse.
	vecDeviceSend = "646d636e2d6465766963652d73656e642d7631002222222222222222222222222222222222222222222222222222222222222222"
)

func TestParityVectorDeviceActions(t *testing.T) {
	subject := bytes.Repeat([]byte{0x21}, 32)
	nonce := bytes.Repeat([]byte{0x22}, 32)
	at := time.Unix(1_700_000_000, 0).UTC()

	got := hex.EncodeToString(deviceActionBytes(ctxDeviceApproval, "Vector@Parity.Example", subject, nonce, at))
	if got != vecDeviceApprove {
		t.Fatalf("approval bytes drifted:\n got %s\nwant %s", got, vecDeviceApprove)
	}

	got = hex.EncodeToString(deviceActionBytes(ctxDeviceRetirement, "Vector@Parity.Example", subject, nonce, time.Time{}))
	if got != vecDeviceRetire {
		t.Fatalf("retirement bytes drifted:\n got %s\nwant %s", got, vecDeviceRetire)
	}

	got = hex.EncodeToString(DeviceChallengeBytes(nonce))
	if got != vecDeviceChallenge {
		t.Fatalf("challenge bytes drifted:\n got %s\nwant %s", got, vecDeviceChallenge)
	}

	got = hex.EncodeToString(DeviceSendBytes(nonce))
	if got != vecDeviceSend {
		t.Fatalf("send-proof bytes drifted:\n got %s\nwant %s", got, vecDeviceSend)
	}

	// An absent time must encode NOTHING rather than a zero, held against the SAME context so the
	// comparison is about the time alone. Getting this wrong would shift every signature by eight
	// bytes between the two encoders, which is the kind of drift nobody thinks to look for.
	withTime := deviceActionBytes(ctxDeviceApproval, "Vector@Parity.Example", subject, nonce, at)
	without := deviceActionBytes(ctxDeviceApproval, "Vector@Parity.Example", subject, nonce, time.Time{})
	if len(withTime)-len(without) != 8 {
		t.Fatalf("an attested time contributed %d bytes, want 8", len(withTime)-len(without))
	}
	if !bytes.HasPrefix(withTime, without) {
		t.Fatal("the attested time must be appended, so an absent one leaves the rest unchanged")
	}
}
