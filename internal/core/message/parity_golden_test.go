package message

import (
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// TestParityGolden pins the canonical wire encoding of the signed split-message
// structures. The golden hex was cross-checked to be byte-identical to the
// frontend's protobufjs encoding (cmd/dmcn-web/web/src/lib/crypto/protobuf.ts),
// which the header signature and body_hash depend on for Go↔browser interop. If
// a proto field is renumbered/reordered, this fails — fix both sides together.
func TestParityGolden(t *testing.T) {
	k32 := make([]byte, 32)
	for i := range k32 {
		k32[i] = byte(i + 1)
	}
	bh := make([]byte, 32)
	for i := range bh {
		bh[i] = byte(0xb0 + i%16)
	}
	h := &dmcnpb.MessageHeader{
		Version:          1,
		MessageId:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ThreadId:         []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		SenderAddress:    "alice@dmcn.me",
		SenderPublicKey:  k32,
		RecipientAddress: "bob@dmcn.me",
		SentAt:           1700000000,
		Subject:          "Hello, 世界",
		AttachmentCount:  1,
		BodySize:         12345,
		Snippet:          "preview text",
		BodyHash:         bh,
	}
	const wantHeader = "080112100102030405060708090a0b0c0d0e0f101a10100f0e0d0c0b0a090807060504030201220d616c69636540646d636e2e6d652a200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20320b626f6240646d636e2e6d653880e2cfaa06420d48656c6c6f2c20e4b896e7958c480150b9605a0c7072657669657720746578746a20b0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b); got != wantHeader {
		t.Errorf("MessageHeader canonical bytes drifted from the browser-parity golden:\n got %s\nwant %s", got, wantHeader)
	}

	// Recipient lists (to=15/cc=16/bcc=17). Two shapes are pinned because the wire
	// distinguishes a sender's Sent self-copy (full bcc) from a recipient copy
	// (empty bcc, omitted entirely by deterministic marshaling) — that omission is
	// what keeps Bcc recipients hidden. Both were cross-checked against protobufjs.
	// Build fresh headers rather than copying h (a proto message embeds a mutex).
	withLists := func(recipientAddr string, bcc []string) *dmcnpb.MessageHeader {
		return &dmcnpb.MessageHeader{
			Version:          1,
			MessageId:        []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			ThreadId:         []byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
			SenderAddress:    "alice@dmcn.me",
			SenderPublicKey:  k32,
			RecipientAddress: recipientAddr,
			SentAt:           1700000000,
			Subject:          "Hello, 世界",
			AttachmentCount:  1,
			BodySize:         12345,
			Snippet:          "preview text",
			BodyHash:         bh,
			To:               []string{"bob@dmcn.me", "carol@dmcn.me"},
			Cc:               []string{"dave@dmcn.me"},
			Bcc:              bcc,
		}
	}
	const wantSelfCopy = "080112100102030405060708090a0b0c0d0e0f101a10100f0e0d0c0b0a090807060504030201220d616c69636540646d636e2e6d652a200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20320d616c69636540646d636e2e6d653880e2cfaa06420d48656c6c6f2c20e4b896e7958c480150b9605a0c7072657669657720746578746a20b0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0b1b2b3b4b5b6b7b8b9babbbcbdbebf7a0b626f6240646d636e2e6d657a0d6361726f6c40646d636e2e6d6582010c6461766540646d636e2e6d658a010b65766540646d636e2e6d65"
	sb, err := proto.MarshalOptions{Deterministic: true}.Marshal(withLists("alice@dmcn.me", []string{"eve@dmcn.me"}))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sb); got != wantSelfCopy {
		t.Errorf("MessageHeader (self-copy, full bcc) canonical bytes drifted from the browser-parity golden:\n got %s\nwant %s", got, wantSelfCopy)
	}

	const wantRcptCopy = "080112100102030405060708090a0b0c0d0e0f101a10100f0e0d0c0b0a090807060504030201220d616c69636540646d636e2e6d652a200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20320b626f6240646d636e2e6d653880e2cfaa06420d48656c6c6f2c20e4b896e7958c480150b9605a0c7072657669657720746578746a20b0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0b1b2b3b4b5b6b7b8b9babbbcbdbebf7a0b626f6240646d636e2e6d657a0d6361726f6c40646d636e2e6d6582010c6461766540646d636e2e6d65"
	rb, err := proto.MarshalOptions{Deterministic: true}.Marshal(withLists("bob@dmcn.me", nil)) // recipient copy: no bcc field at all
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(rb); got != wantRcptCopy {
		t.Errorf("MessageHeader (recipient-copy, no bcc) canonical bytes drifted from the browser-parity golden:\n got %s\nwant %s", got, wantRcptCopy)
	}

	c := &dmcnpb.MessageContent{Body: &dmcnpb.MessageBody{ContentType: "text/plain", Content: []byte("the body 世界")}}
	const wantContent = "0a1d0a0a746578742f706c61696e120f74686520626f647920e4b896e7958c"
	cb, err := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(cb); got != wantContent {
		t.Errorf("MessageContent canonical bytes drifted from the browser-parity golden:\n got %s\nwant %s", got, wantContent)
	}
}
