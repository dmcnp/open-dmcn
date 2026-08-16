package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/core/onion"
	"dmcn.dev/open-dmcn/dmcnpb"
)

// onionSeenTTL bounds how long a forwarded packet's hash is remembered for
// dedup. Generous relative to onion TTLs so a retried packet within its lifetime
// is still recognized as a duplicate.
const onionSeenTTL = 10 * time.Minute

// handleOnion peels one onion layer with the relay's onion key and either
// forwards the inner packet to the next hop or, at the final hop, delivers the
// inner StoreRequest. It is idempotent: a duplicate packet is ACKed without
// re-processing. Returns a hop-by-hop ACK (or an error response).
func (r *Relay) handleOnion(predecessor peer.ID, req *dmcnpb.OnionForwardRequest) *dmcnpb.RelayResponse {
	if !r.onionEnabled {
		return errorResponse("ONION_DISABLED", "this relay does not forward onion traffic")
	}
	pkt := req.GetPacket()
	if pkt == nil {
		return errorResponse("INVALID_REQUEST", "missing onion packet")
	}

	// Dedup by packet hash (idempotent forwarding / silent duplicate discard).
	pktBytes, err := proto.Marshal(pkt)
	if err != nil {
		return errorResponse("INVALID_REQUEST", "marshal onion packet")
	}
	hash := crypto.SHA256Hash(pktBytes)
	if r.onionAlreadySeen(hash) {
		return onionAck()
	}

	layer, err := onion.PeelOnion(r.onionPriv, pkt)
	if err != nil {
		return errorResponse("ONION_PEEL", "cannot peel onion layer")
	}

	// Drop expired packets.
	if layer.TtlUnix != 0 && time.Now().Unix() > layer.TtlUnix {
		return errorResponse("ONION_EXPIRED", "onion packet expired")
	}

	r.markOnionSeen(hash)
	r.onionDelay() // timing-correlation jitter (no-op when unconfigured)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if layer.NextHop == onion.DeliverHop {
		// Distinguish a genuine mesh delivery (predecessor is a relay) from a 1-hop
		// self-delivery (predecessor is a client), so RequireOnion can't be bypassed
		// by wrapping a direct send in a single layer. With no checker wired, trust
		// the onion path.
		arrival := arrivalOnionRelay
		if r.isRelayPeer != nil && !r.isRelayPeer(predecessor) {
			arrival = arrivalOnionClient
		}
		return r.onionDeliver(ctx, layer.GetDelivery(), arrival)
	}
	return r.onionForward(ctx, layer.NextHop, layer.GetInner())
}

// onionDeliver executes the final-hop StoreRequest carried in the innermost layer
// — the same path a direct STORE takes (sender signature verified, routed to the
// mailbox/transient store).
func (r *Relay) onionDeliver(ctx context.Context, deliveryBytes []byte, arrival onionArrival) *dmcnpb.RelayResponse {
	if len(deliveryBytes) == 0 {
		return errorResponse("ONION_DELIVER", "empty delivery payload")
	}
	sr := &dmcnpb.StoreRequest{}
	if err := proto.Unmarshal(deliveryBytes, sr); err != nil {
		return errorResponse("ONION_DELIVER", "malformed delivery payload")
	}
	env, err := message.EncryptedEnvelopeFromProto(sr.Envelope)
	if err != nil {
		return errorResponse("ONION_DELIVER", "malformed envelope")
	}
	envBytes, err := proto.Marshal(sr.Envelope)
	if err != nil {
		return errorResponse("ONION_DELIVER", "marshal envelope")
	}
	envHash := crypto.SHA256Hash(envBytes)
	resp := r.acceptEnvelope(ctx, sr.SenderAddress, sr.SenderSignature, env, envHash, arrival)
	if resp.GetError() != nil {
		return resp // surface the STORE failure to the predecessor
	}
	r.log.Debugf("onion delivered envelope %x", envHash)
	return onionAck()
}

// onionForward dials the next hop and passes the inner packet on.
func (r *Relay) onionForward(ctx context.Context, nextHop string, inner *dmcnpb.OnionPacket) *dmcnpb.RelayResponse {
	if inner == nil {
		return errorResponse("ONION_FORWARD", "forward layer has no inner packet")
	}
	nextID, err := peer.Decode(nextHop)
	if err != nil {
		return errorResponse("ONION_FORWARD", "invalid next hop")
	}
	if err := r.ClientOnionForward(ctx, nextID, inner); err != nil {
		r.log.Warnf("onion forward to %s failed: %v", nextHop, err)
		return errorResponse("ONION_FORWARD", "next hop unreachable")
	}
	return onionAck()
}

// ClientOnionForward sends an onion packet to the next relay and waits for its
// hop-by-hop ACK.
func (r *Relay) ClientOnionForward(ctx context.Context, peerID peer.ID, pkt *dmcnpb.OnionPacket) error {
	s, err := r.host.NewStream(ctx, peerID, ProtocolID)
	if err != nil {
		return err
	}
	defer s.Close()

	req := &dmcnpb.RelayRequest{Request: &dmcnpb.RelayRequest_OnionForward{
		OnionForward: &dmcnpb.OnionForwardRequest{Packet: pkt},
	}}
	if err := writeRequest(s, req); err != nil {
		return err
	}
	resp, err := readResponse(s)
	if err != nil {
		return err
	}
	if of := resp.GetOnionForward(); of != nil && of.Accepted {
		return nil
	}
	if e := resp.GetError(); e != nil {
		return fmt.Errorf("relay: onion forward: %s: %s", e.Code, e.Message)
	}
	return errors.New("relay: onion forward: unexpected response")
}

func onionAck() *dmcnpb.RelayResponse {
	return &dmcnpb.RelayResponse{Response: &dmcnpb.RelayResponse_OnionForward{
		OnionForward: &dmcnpb.OnionForwardResponse{Accepted: true},
	}}
}

// onionDelay sleeps a random duration in [0, onionJitter) to blur per-hop timing
// correlation. A no-op when jitter is unconfigured.
func (r *Relay) onionDelay() {
	if r.onionJitter <= 0 {
		return
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(r.onionJitter)))
	if err != nil {
		return
	}
	time.Sleep(time.Duration(n.Int64()))
}

func (r *Relay) onionAlreadySeen(hash [32]byte) bool {
	r.onionMu.Lock()
	defer r.onionMu.Unlock()
	_, ok := r.onionSeen[hash]
	return ok
}

func (r *Relay) markOnionSeen(hash [32]byte) {
	now := time.Now()
	r.onionMu.Lock()
	defer r.onionMu.Unlock()
	// Opportunistic prune of expired entries.
	for h, at := range r.onionSeen {
		if now.Sub(at) > onionSeenTTL {
			delete(r.onionSeen, h)
		}
	}
	r.onionSeen[hash] = now
}
