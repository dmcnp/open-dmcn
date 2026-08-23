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
// nonce; List/Body/Delete verify the caller's signature over that nonce against the address's
// Ed25519 key before touching the mailbox (keyed by the address's X25519 public key in hex).
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

// authorize verifies the signature over the server-issued nonce against address's record and
// returns the mailbox key (hex of the record's X25519 public key) on success.
func (p *inProcRelay) authorize(ctx context.Context, address string, nonce, signature []byte) (string, error) {
	rec, err := p.lookup(ctx, address)
	if err != nil {
		return "", err
	}
	if err := crypto.Verify(rec.Ed25519Public, nonce, signature); err != nil {
		return "", fmt.Errorf("mailbox auth: signature verification failed")
	}
	return fmt.Sprintf("%x", rec.X25519Public[:]), nil
}

func (p *inProcRelay) List(ctx context.Context, address string, nonce, signature []byte, limit int, cursor []byte) ([]*dmcnpb.MailboxEntry, []byte, error) {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return nil, nil, err
	}
	entries, next, err := p.node.Relay().Mailbox().List(ctx, rxHex, limit, string(cursor))
	if err != nil {
		return nil, nil, err
	}
	return entries, []byte(next), nil
}

func (p *inProcRelay) Body(ctx context.Context, address string, nonce, signature []byte, hash [32]byte) (*dmcnpb.MailboxBody, error) {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return nil, err
	}
	return p.node.Relay().Mailbox().GetBody(ctx, rxHex, hash)
}

func (p *inProcRelay) Delete(ctx context.Context, address string, nonce, signature []byte, hash [32]byte) error {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return err
	}
	return p.node.Relay().Mailbox().Delete(ctx, rxHex, hash)
}

// --- Personal storage ---------------------------------------------------------------------
//
// Each op authorises exactly like the mail ops above — the browser signs a server-issued nonce —
// then delegates to the Relay, which is also what the libp2p stream handler calls. Quota lives
// there rather than here, so the in-process and over-the-wire paths cannot drift apart.

func (p *inProcRelay) KvGet(ctx context.Context, address string, nonce, signature []byte, key string) ([]byte, uint64, bool, error) {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return nil, 0, false, err
	}
	return p.node.Relay().KvGet(ctx, rxHex, key)
}

func (p *inProcRelay) KvPut(ctx context.Context, address string, nonce, signature []byte, key string, sealed []byte, expectedVersion uint64) (uint64, error) {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return 0, err
	}
	return p.node.Relay().KvPut(ctx, rxHex, key, sealed, expectedVersion)
}

func (p *inProcRelay) KvList(ctx context.Context, address string, nonce, signature []byte, prefix string, limit int, cursor string, values bool) ([]relay.KvItem, string, error) {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return nil, "", err
	}
	return p.node.Relay().KvList(ctx, rxHex, prefix, limit, cursor, values)
}

func (p *inProcRelay) KvDelete(ctx context.Context, address string, nonce, signature []byte, key string) error {
	rxHex, err := p.authorize(ctx, address, nonce, signature)
	if err != nil {
		return err
	}
	return p.node.Relay().KvDelete(ctx, rxHex, key)
}

func (p *inProcRelay) KvStat(ctx context.Context, address string, nonce, signature []byte) (used, quota, count uint64, err error) {
	rxHex, aerr := p.authorize(ctx, address, nonce, signature)
	if aerr != nil {
		return 0, 0, 0, aerr
	}
	return p.node.Relay().KvStat(ctx, rxHex)
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
	return err
}
