package onion

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
)

// DeliverHop is the sentinel next_hop value at the innermost layer, telling the
// final relay to deliver (STORE) rather than forward.
const DeliverHop = "DELIVER"

// onionVersion is the wire version of the onion packet format.
// onionVersion is the wire version of the onion packet format, and doubles as the layer
// key-derivation generation a peeling relay dispatches on (onion.LayerKDFv2).
const onionVersion = 2

// layerSizeClasses bucket the DELIVERY (innermost) layer's plaintext, so the
// message size is hidden among all messages in the same class. Mirrors the message
// layer's classes (§15.3.3). Only the innermost layer is bucketed — the outer
// (forwarding) layers add just their real routing overhead (~tens of bytes), so a
// 3-hop message is ~3× its size class on the wire (the inherent cost of sending it
// to three hops), NOT a per-hop bucket multiplication. Bucketing the outer layers
// too would buy nothing — a relay learns whether it is the exit from the decrypted
// next_hop, not from packet size — while making each hop cascade to the next class.
//
// The top class (36 MB) sits just above the ~35 MB message-size ceiling (with
// headroom for envelope/StoreRequest framing), so a ceiling-sized delivery lands
// in one class rather than the size-leaking round-to-MB fallback.
//
// Residual gap vs §18: this is per-layer bucketing, not Sphinx fixed-size packets;
// layers still differ by ~routing overhead hop-to-hop. See the package doc.
var layerSizeClasses = []uint32{
	1024,             // 1 KB
	4 * 1024,         // 4 KB
	16 * 1024,        // 16 KB
	64 * 1024,        // 64 KB
	256 * 1024,       // 256 KB
	1024 * 1024,      // 1 MB
	4 * 1024 * 1024,  // 4 MB
	16 * 1024 * 1024, // 16 MB
	36 * 1024 * 1024, // 36 MB — top class; ~35 MB message ceiling + framing headroom
}

// layerBucket returns the bucketed size for a delivery plaintext of payloadLen
// bytes: the smallest size class that fits payloadLen+4 (the length prefix), or —
// above the top class — payloadLen rounded up to the nearest MB.
func layerBucket(payloadLen int) uint32 {
	needed := uint32(payloadLen) + 4
	for _, sc := range layerSizeClasses {
		if needed <= sc {
			return sc
		}
	}
	mb := uint32(1024 * 1024)
	return ((needed + mb - 1) / mb) * mb
}

// frameLayer prepends a 4-byte length to b. When toClass is set (the innermost
// delivery layer) it also zero-pads to b's size class; otherwise (forwarding
// layers) it adds only the prefix, so an outer layer grows by just its routing
// overhead rather than re-bucketing the padded inner packet. unpadLayer reverses
// both via the length prefix.
func frameLayer(b []byte, toClass bool) []byte {
	size := uint32(len(b)) + 4
	if toClass {
		size = layerBucket(len(b))
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func unpadLayer(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, errors.New("onion: layer too short")
	}
	n := binary.BigEndian.Uint32(padded[:4])
	if int(n)+4 > len(padded) {
		return nil, errors.New("onion: layer length out of range")
	}
	return padded[4 : 4+n], nil
}

// Hop identifies one relay on a route: its peer ID and onion X25519 public key
// (both from its RelayDescriptor).
type Hop struct {
	PeerID    string
	X25519Pub [32]byte
}

// BuildOnion layers a delivery payload for the given route, encrypting from the
// innermost hop outward. route is ordered entry→…→exit; the exit hop performs the
// final delivery (a marshaled StoreRequest in `delivery`). The returned packet is
// what the sender submits to route[0]. ttl is the absolute expiry stamped into
// every layer.
func BuildOnion(route []Hop, delivery []byte, ttl time.Time) (*dmcnpb.OnionPacket, error) {
	if len(route) == 0 {
		return nil, errors.New("onion: empty route")
	}

	// Innermost layer (exit): deliver.
	exit := route[len(route)-1]
	layer := &dmcnpb.OnionLayer{
		NextHop:  DeliverHop,
		TtlUnix:  ttl.Unix(),
		Delivery: delivery,
	}
	// Only the innermost (delivery) layer is bucketed to a size class — that hides
	// the message size. Outer layers add just routing overhead (see frameLayer).
	pkt, err := sealOnionLayer(exit.X25519Pub, layer, true)
	if err != nil {
		return nil, err
	}

	// Wrap outward: each hop's layer names the *next* hop and carries the next
	// hop's packet as `inner`.
	for i := len(route) - 2; i >= 0; i-- {
		next := route[i+1]
		layer := &dmcnpb.OnionLayer{
			NextHop: next.PeerID,
			TtlUnix: ttl.Unix(),
			Inner:   pkt,
		}
		pkt, err = sealOnionLayer(route[i].X25519Pub, layer, false)
		if err != nil {
			return nil, err
		}
	}
	return pkt, nil
}

func sealOnionLayer(hopPub [32]byte, layer *dmcnpb.OnionLayer, bucket bool) (*dmcnpb.OnionPacket, error) {
	plain, err := proto.Marshal(layer)
	if err != nil {
		return nil, fmt.Errorf("onion: marshal layer: %w", err)
	}
	sl, err := SealLayer(hopPub, frameLayer(plain, bucket), onionVersion)
	if err != nil {
		return nil, err
	}
	return &dmcnpb.OnionPacket{
		Version:        onionVersion,
		EphemeralPub:   sl.EphemeralXPub[:],
		Nonce:          sl.Nonce[:],
		Tag:            sl.Tag[:],
		EncryptedLayer: sl.Ciphertext,
	}, nil
}

// PeelOnion opens this relay's layer with its onion X25519 private key, returning
// the decrypted OnionLayer (next_hop + inner packet or delivery payload).
func PeelOnion(relayPriv [32]byte, pkt *dmcnpb.OnionPacket) (*dmcnpb.OnionLayer, error) {
	if pkt == nil {
		return nil, errors.New("onion: nil packet")
	}
	if len(pkt.EphemeralPub) != 32 || len(pkt.Nonce) != 12 || len(pkt.Tag) != 16 {
		return nil, errors.New("onion: malformed packet")
	}
	var sl SealedLayer
	copy(sl.EphemeralXPub[:], pkt.EphemeralPub)
	copy(sl.Nonce[:], pkt.Nonce)
	copy(sl.Tag[:], pkt.Tag)
	sl.Ciphertext = pkt.EncryptedLayer

	padded, err := OpenLayer(relayPriv, &sl, pkt.Version)
	if err != nil {
		return nil, err
	}
	plain, err := unpadLayer(padded)
	if err != nil {
		return nil, err
	}
	layer := &dmcnpb.OnionLayer{}
	if err := proto.Unmarshal(plain, layer); err != nil {
		return nil, fmt.Errorf("onion: unmarshal layer: %w", err)
	}
	return layer, nil
}
