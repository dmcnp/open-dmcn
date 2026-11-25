package main

import (
	"context"
	"errors"
	"fmt"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/relay"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
)

// relayadapter.go bridges the webmail backend to the daemon's OWN node, in-process. The
// product's web backend is a separate libp2p client that dials a relay; here the backend and
// the relay live in one process, and a libp2p host cannot dial itself. So instead of the
// Client* stream methods, these adapters call the relay's server-side surface directly
// (StoreLocal, Mailbox().List/GetBody/Delete) — while preserving zero-knowledge: the browser
// still signs a per-op nonce, verified here against the address's resolved record. The server
// holds no user private key.

// addressLookup resolves an address to its verified IdentityRecord (the node's fleet resolver).
type addressLookup func(ctx context.Context, address string) (*identity.IdentityRecord, error)

// inProcRelay implements webapi.RelayProxy against the local mailbox. Challenge issues a fresh
// nonce; every op then goes through the relay's own gate (Relay.AuthorizeMailbox), which is
// also what the libp2p stream handler calls, so the two ways into a mailbox can't disagree
// about who is let in.
type inProcRelay struct {
	node   *node.Node
	lookup addressLookup
}

func newInProcRelay(n *node.Node, lookup addressLookup) *inProcRelay {
	return &inProcRelay{node: n, lookup: lookup}
}

// Challenge returns a fresh single-use nonce for a mailbox op on address. It resolves the
// record up front so an unknown address fails here rather than after the client signs.
func (p *inProcRelay) Challenge(ctx context.Context, address string) ([]byte, error) {
	if _, err := p.lookup(ctx, address); err != nil {
		return nil, err
	}
	return crypto.RandomBytes(32)
}

// authorize puts a request through the mailbox gate and returns the mailbox key (hex of the
// record's X25519 public key) and the active device that signed, if one did.
func (p *inProcRelay) authorize(ctx context.Context, address string, proof relay.MailboxProof, class relay.OpClass) (rxHex string, device []byte, err error) {
	rec, err := p.lookup(ctx, address)
	if err != nil {
		return "", nil, err
	}
	device, err = p.node.Relay().AuthorizeMailbox(ctx, rec, proof, class)
	if err != nil {
		return "", nil, err
	}
	return fmt.Sprintf("%x", rec.X25519Public[:]), device, nil
}

func (p *inProcRelay) List(ctx context.Context, address string, proof relay.MailboxProof, limit int, cursor []byte) ([]*dmcnpb.MailboxEntry, []byte, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassDevice)
	if err != nil {
		return nil, nil, err
	}
	entries, next, err := p.node.Relay().Mailbox().List(ctx, rxHex, limit, string(cursor), relay.ListNewestFirst)
	if err != nil {
		return nil, nil, err
	}
	return entries, []byte(next), nil
}

func (p *inProcRelay) Body(ctx context.Context, address string, proof relay.MailboxProof, hash [32]byte) (*dmcnpb.MailboxBody, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassDevice)
	if err != nil {
		return nil, err
	}
	return p.node.Relay().Mailbox().GetBody(ctx, rxHex, hash)
}

func (p *inProcRelay) Delete(ctx context.Context, address string, proof relay.MailboxProof, hash [32]byte) error {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassOwner)
	if err != nil {
		return err
	}
	return p.node.Relay().Mailbox().Delete(ctx, rxHex, hash)
}

// --- Personal storage ---------------------------------------------------------------------
//
// Each op is gated like the mail ops above, then delegates to the Relay, which is also what
// the libp2p stream handler calls. Quota lives there rather than here, so the in-process and
// over-the-wire paths cannot drift apart.

func (p *inProcRelay) KvGet(ctx context.Context, address string, proof relay.MailboxProof, key string) (relay.KvItem, bool, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassDevice)
	if err != nil {
		return relay.KvItem{}, false, err
	}
	return p.node.Relay().KvGet(ctx, rxHex, key)
}

func (p *inProcRelay) KvPut(ctx context.Context, address string, proof relay.MailboxProof, key string, sealed []byte, expectedVersion uint64) (uint64, error) {
	rxHex, device, err := p.authorize(ctx, address, proof, relay.KvPutClass(key))
	if err != nil {
		return 0, err
	}
	return p.node.Relay().KvPut(ctx, rxHex, key, sealed, expectedVersion, device)
}

func (p *inProcRelay) KvList(ctx context.Context, address string, proof relay.MailboxProof, prefix string, limit int, cursor string, values bool) ([]relay.KvItem, string, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassDevice)
	if err != nil {
		return nil, "", err
	}
	return p.node.Relay().KvList(ctx, rxHex, prefix, limit, cursor, values)
}

func (p *inProcRelay) KvDelete(ctx context.Context, address string, proof relay.MailboxProof, key string) error {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.KvDeleteClass(key))
	if err != nil {
		return err
	}
	return p.node.Relay().KvDelete(ctx, rxHex, key)
}

func (p *inProcRelay) KvStat(ctx context.Context, address string, proof relay.MailboxProof) (used, quota, count uint64, err error) {
	rxHex, _, aerr := p.authorize(ctx, address, proof, relay.ClassDevice)
	if aerr != nil {
		return 0, 0, 0, aerr
	}
	return p.node.Relay().KvStat(ctx, rxHex)
}

// --- Device registry ------------------------------------------------------------------------

func (p *inProcRelay) DeviceEnroll(ctx context.Context, address string, proof relay.MailboxProof, op *dmcnpb.MailboxDeviceEnrollOp) (*dmcnpb.DeviceRecord, bool, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassEnroll)
	if err != nil {
		return nil, false, err
	}
	return p.node.Relay().DeviceEnroll(ctx, rxHex, address, op, proof.Nonce)
}

func (p *inProcRelay) DeviceList(ctx context.Context, address string, proof relay.MailboxProof) ([]*dmcnpb.DeviceRecord, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassOwner)
	if err != nil {
		return nil, err
	}
	return p.node.Relay().DeviceList(ctx, rxHex, address)
}

func (p *inProcRelay) DeviceRetire(ctx context.Context, address string, proof relay.MailboxProof, op *dmcnpb.MailboxDeviceRetireOp) (*dmcnpb.DeviceRecord, error) {
	rxHex, _, err := p.authorize(ctx, address, proof, relay.ClassOwner)
	if err != nil {
		return nil, err
	}
	return p.node.Relay().DeviceRetire(ctx, rxHex, address, op, proof.Nonce)
}

// newSendGate is the device check for a send made through this server. The sender is one of
// this node's own accounts, so its registry is here. The sender's signature over the envelope
// hash is checked first: the gate only means something for a send the account key made.
func newSendGate(n *node.Node, lookup addressLookup) webapi.SendGate {
	return func(ctx context.Context, senderAddr string, envHash, signature, devicePub, deviceSig []byte) error {
		rec, err := lookup(ctx, senderAddr)
		if err != nil {
			return err
		}
		if err := crypto.Verify(rec.Ed25519Public, envHash, signature); err != nil {
			return &relay.OpError{Code: "AUTH_FAILED", Message: "the sender's signature does not verify"}
		}
		return n.Relay().AuthorizeSend(ctx, rec, envHash, devicePub, deviceSig)
	}
}

// inProcRouter implements webapi.RelayRouter. A STORE whose hint resolves to this node is
// accepted locally (no self-dial); a hint for another node is dialed like the product client.
// This lets the same daemon serve a purely self-hosted domain (sender + recipient co-located)
// and federate with other nodes when hints point elsewhere.
type inProcRouter struct {
	node *node.Node
}

func newInProcRouter(n *node.Node) *inProcRouter { return &inProcRouter{node: n} }

// isLocal reports whether a relay hint names this node.
func (r *inProcRouter) isLocal(hint string) (bool, error) {
	info, err := node.ParseRelayHint(hint)
	if err != nil {
		return false, err
	}
	return info.ID == r.node.PeerID(), nil
}

func (r *inProcRouter) ConnectPeer(addr string) error {
	local, err := r.isLocal(addr)
	if err != nil {
		return err
	}
	if local {
		return nil // the local mailbox needs no dial
	}
	return r.node.ConnectPeer(addr)
}

func (r *inProcRouter) StorePreSignedOnPeer(ctx context.Context, hint, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
	local, err := r.isLocal(hint)
	if err != nil {
		return [32]byte{}, err
	}
	if local {
		hash, serr := r.node.Relay().StoreLocal(ctx, senderAddr, signature, env)
		return hash, mapStoreErr(serr)
	}
	info, err := node.ParseRelayHint(hint)
	if err != nil {
		return [32]byte{}, err
	}
	hash, serr := r.node.Relay().ClientStorePreSigned(ctx, info.ID, senderAddr, signature, env)
	return hash, mapStoreErr(serr)
}

func (r *inProcRouter) SendOnionPreSigned(ctx context.Context, senderAddr string, signature []byte, recipientRec *identity.IdentityRecord, env *message.EncryptedEnvelope) ([32]byte, error) {
	// relaxed=true: tolerate small/co-located relay sets (a self-host may have too few relays
	// to build a diverse 3-hop route until it federates). Onion is inert until >=3 relays exist.
	return r.node.SendOnionPreSigned(ctx, senderAddr, signature, recipientRec, env, true)
}

// mapStoreErr translates relay STORE sentinels into the webapi ones so the send handler can
// surface a full recipient mailbox distinctly (507), keeping the api package decoupled from relay.
func mapStoreErr(err error) error {
	if errors.Is(err, relay.ErrMailboxFull) {
		return webapi.ErrMailboxFull
	}
	if errors.Is(err, relay.ErrRecipientClosed) {
		return webapi.ErrRecipientClosed
	}
	return err
}
