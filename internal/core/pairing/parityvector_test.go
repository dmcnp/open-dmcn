package pairing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"google.golang.org/protobuf/proto"
)

// Known-answer vectors for the pairing wire values a client produces by itself
// (cmd/dmcnd/web/src/lib/crypto/pairing.ts, whose test carries the same constants) and this
// package reads: the request and response payloads, and the self-signed throwaway record the new
// device publishes. The confirmation code is pinned separately by goldenSAS in pairing_test.go.
//
// Fixed inputs: Ed25519 seed 32x0x0b (public key below), X25519 public 32x0x08 / private
// 32x0x0d, device id 16x0x03, created 1700000000; request keys 32x0x01 / 32x0x02, label
// "vector device", requested at 1700000000; ephemeral address pair-0102030405060708@pairing.local,
// one relay hint, now = 1700000000 (so expiry = 1700000900). Ed25519 signing is deterministic,
// so the whole signed record is a fixed byte string.
const (
	vecEd25519Pub   = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
	vecCloneReq     = "0a200101010101010101010101010101010101010101010101010101010101010101122002020202020202020202020202020202020202020202020202020202020202021a1003030303030303030303030303030303220d766563746f72206465766963652880e2cfaa06"
	vecCloneResp    = "0a15766563746f72407061726974792e6578616d706c65122066be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a1a400b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a222008080808080808080808080808080808080808080808080808080808080808082a200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d3210030303030303030303030303030303033880e2cfaa06"
	vecEphemeralRec = "08011223706169722d303130323033303430353036303730384070616972696e672e6c6f63616c1a2066be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a222008080808080808080808080808080808080808080808080808080808080808082880e2cfaa063084e9cfaa063a5c2f646e73342f72656c61792e7061726974792e6578616d706c652f7463702f373430302f7032702f313244334b6f6f574e6e55315332424d6e636247705050715768505a51514b4e744e6d4835596e4361487576746936787a56624c5240abb730ff19358cf4ccdf57c5581f1885509dbf22ebfd0a2782248771058f82c25707596dfa9c6d66d96e2bb53893c0bd334df0d9ce81323f16646a7edfa93004d00101"
	vecRelayHint    = "/dns4/relay.parity.example/tcp/7400/p2p/12D3KooWNnU1S2BMncbGpPPqWhPZQQKNtNmH5YnCaHuvti6xzVbL"
)

// vectorKeyPair is the fixed account/ephemeral key pair every vector uses.
func vectorKeyPair() *identity.IdentityKeyPair {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x0b}, 32))
	kp := &identity.IdentityKeyPair{Ed25519Public: priv.Public().(ed25519.PublicKey), Ed25519Private: priv, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}
	for i := range kp.X25519Public {
		kp.X25519Public[i] = 0x08
		kp.X25519Private[i] = 0x0d
	}
	for i := range kp.DeviceID {
		kp.DeviceID[i] = 0x03
	}
	return kp
}

func TestParityVectorKeyPair(t *testing.T) {
	if got := hex.EncodeToString(vectorKeyPair().Ed25519Public); got != vecEd25519Pub {
		t.Fatalf("public key for seed 0x0b: %s", got)
	}
}

func TestParityVectorCloneRequest(t *testing.T) {
	got, err := MarshalCloneRequest(&CloneRequestData{
		EphemeralEd25519Pub: bytes.Repeat([]byte{0x01}, 32),
		EphemeralX25519Pub:  [32]byte(bytes.Repeat([]byte{0x02}, 32)),
		DeviceID:            [16]byte(bytes.Repeat([]byte{0x03}, 16)),
		Label:               "vector device",
		RequestedAt:         time.Unix(1_700_000_000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vecCloneReq {
		t.Fatalf("clone request drifted:\n got %s\nwant %s", hex.EncodeToString(got), vecCloneReq)
	}
	back, err := unmarshalCloneRequest(got)
	if err != nil || back.Label != "vector device" || back.RequestedAt.Unix() != 1_700_000_000 {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}

func TestParityVectorCloneResponse(t *testing.T) {
	kp := vectorKeyPair()
	got, err := MarshalCloneResponse(&CloneResponseData{
		Address: "vector@parity.example", Ed25519Public: kp.Ed25519Public, Ed25519Private: kp.Ed25519Private,
		X25519Public: kp.X25519Public, X25519Private: kp.X25519Private, DeviceID: kp.DeviceID, CreatedAt: kp.CreatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vecCloneResp {
		t.Fatalf("clone response drifted:\n got %s\nwant %s", hex.EncodeToString(got), vecCloneResp)
	}
}

func TestParityVectorEphemeralRecord(t *testing.T) {
	rec, err := NewEphemeralRecord("pair-0102030405060708@pairing.local", vectorKeyPair(), vecRelayHint, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	got, err := proto.MarshalOptions{Deterministic: true}.Marshal(rec.ToProto())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != vecEphemeralRec {
		t.Fatalf("ephemeral record drifted:\n got %s\nwant %s", hex.EncodeToString(got), vecEphemeralRec)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("pinned record no longer self-verifies: %v", err)
	}
}
