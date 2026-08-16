package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// NOTE (open-dmcn reference implementation): native send-cap / send-rate enforcement
// (the product ConsumeSend counter + operator send-limits) is omitted. A self-hoster is
// their own send authority.

// RelayRouter provides the ability to connect to peers and store envelopes on
// remote relays identified by their peer ID.
type RelayRouter interface {
	ConnectPeer(addr string) error
	StorePreSignedOnPeer(ctx context.Context, peerID string, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error)
	// SendOnionPreSigned delivers the envelope to the recipient via a fixed 3-hop
	// onion route ending at the recipient's relay. The signature (over the envelope
	// hash) is produced in the browser; the onion layers use only ephemeral keys +
	// relay public keys, so no user key material reaches the server.
	SendOnionPreSigned(ctx context.Context, senderAddr string, signature []byte, recipientRec *identity.IdentityRecord, env *message.EncryptedEnvelope) ([32]byte, error)
}

// MessageHandler handles outbound message send (STORE to the recipient's relay).
type MessageHandler struct {
	storePreSigned func(ctx context.Context, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error)
	registryLookup func(ctx context.Context, address string) (*identity.IdentityRecord, error)
	relayRouter    RelayRouter
	// replicates reports whether the recipient's domain declares mailbox replication
	// (DAR PolicyReplicateMailbox). nil ⇒ always failover.
	replicates func(ctx context.Context, address string) bool
	// verifyRouting checks the recipient's RelayHints are attested by a verified operator
	// routing credential before we STORE to them (defeats forged-routing mail redirection).
	// nil ⇒ skipped (tests / a self-host node that signs its own routing).
	verifyRouting func(ctx context.Context, rec *identity.IdentityRecord) error
	log           logr.Logger
}

// NewMessageHandler creates a new MessageHandler.
func NewMessageHandler(
	storePreSigned func(ctx context.Context, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error),
	registryLookup func(ctx context.Context, address string) (*identity.IdentityRecord, error),
	relayRouter RelayRouter,
	replicates func(ctx context.Context, address string) bool,
	verifyRouting func(ctx context.Context, rec *identity.IdentityRecord) error,
	log logr.Logger,
) *MessageHandler {
	return &MessageHandler{
		storePreSigned: storePreSigned,
		registryLookup: registryLookup,
		relayRouter:    relayRouter,
		replicates:     replicates,
		verifyRouting:  verifyRouting,
		log:            log,
	}
}

// sendRequest is the JSON body for HandleSend.
type sendRequest struct {
	SenderAddress    string `json:"sender_address"`
	SenderSignature  string `json:"sender_signature"`
	Envelope         string `json:"envelope"`
	RecipientAddress string `json:"recipient_address"`
	// Onion requests 3-hop onion-routed delivery. The server also forces onion
	// when the recipient's record sets RequireOnion (stricter-wins).
	Onion bool `json:"onion"`
}

// HandleSend handles sending a message.
func (h *MessageHandler) HandleSend(w http.ResponseWriter, r *http.Request) {
	address := webcore.AddressFromContext(r.Context())
	if address == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req sendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Verify sender address matches session.
	if req.SenderAddress != address {
		writeError(w, http.StatusForbidden, "sender address does not match session")
		return
	}

	// Decode envelope protobuf from base64.
	envBytes, err := base64.StdEncoding.DecodeString(req.Envelope)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope encoding")
		return
	}

	var pbEnv dmcnpb.EncryptedEnvelope
	if err := proto.Unmarshal(envBytes, &pbEnv); err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope protobuf: "+err.Error())
		return
	}

	env, err := message.EncryptedEnvelopeFromProto(&pbEnv)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid envelope: "+err.Error())
		return
	}

	// Decode signature from base64.
	sigBytes, err := base64.StdEncoding.DecodeString(req.SenderSignature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signature encoding")
		return
	}

	// Route STORE to recipient's relay hints if recipient_address is provided.
	var hash [32]byte
	if req.RecipientAddress != "" && h.registryLookup != nil && h.relayRouter != nil {
		recipientRec, lookupErr := h.registryLookup(r.Context(), req.RecipientAddress)
		if lookupErr != nil {
			writeError(w, http.StatusBadRequest, "recipient not found")
			return
		}
		if len(recipientRec.RelayHints) == 0 {
			writeError(w, http.StatusBadRequest, "recipient has no relay hints")
			return
		}
		// Routing integrity: the hints are operator-owned and unsigned by the owner, so verify
		// they are attested by a routing credential that chains to the domain DAR before we STORE
		// to them — otherwise a forged record could redirect this mail to attacker relays.
		if h.verifyRouting != nil {
			if err := h.verifyRouting(r.Context(), recipientRec); err != nil {
				h.log.Warn("recipient routing verification failed", logr.M("recipient", req.RecipientAddress), logr.M("error", err.Error()))
				writeError(w, http.StatusBadGateway, "recipient routing could not be verified")
				return
			}
		}

		// Onion-route when the sender opts in or the recipient requires it. No
		// silent downgrade: if onion is requested/required and fails, the send fails.
		if req.Onion || recipientRec.RequireOnion {
			onionHash, onionErr := h.relayRouter.SendOnionPreSigned(r.Context(), req.SenderAddress, sigBytes, recipientRec, env)
			if onionErr != nil {
				h.log.Error("onion send failed", logr.M("error", onionErr.Error()))
				writeError(w, http.StatusBadGateway, "failed to deliver message via onion routing: "+onionErr.Error())
				return
			}
			hash = onionHash
		} else {
			// Replicate to every reachable hint when the recipient's domain opts in
			// (FETCH merges + dedups); otherwise first reachable wins (failover).
			replicate := h.replicates != nil && h.replicates(r.Context(), req.RecipientAddress)
			var lastErr error
			stored := 0
			for _, hint := range recipientRec.RelayHints {
				if connectErr := h.relayRouter.ConnectPeer(hint); connectErr != nil {
					lastErr = connectErr
					continue
				}
				hsh, serr := h.relayRouter.StorePreSignedOnPeer(r.Context(), hint, req.SenderAddress, sigBytes, env)
				if serr != nil {
					// A full mailbox is a per-account verdict, not a per-relay fault: surface it
					// distinctly (507) so the sender sees "recipient mailbox full".
					if errors.Is(serr, ErrMailboxFull) {
						h.log.Warn("recipient mailbox full", logr.M("recipient", req.RecipientAddress))
						writeError(w, http.StatusInsufficientStorage, "recipient mailbox is full")
						return
					}
					lastErr = serr
					continue
				}
				hash = hsh
				stored++
				if !replicate {
					break
				}
			}
			if stored == 0 {
				h.log.Error("failed to store envelope on any relay", logr.M("error", lastErr.Error()))
				writeError(w, http.StatusBadGateway, "failed to deliver message to recipient relays")
				return
			}
		}
	} else {
		// Fallback to default relay.
		var storeErr error
		hash, storeErr = h.storePreSigned(r.Context(), req.SenderAddress, sigBytes, env)
		if storeErr != nil {
			h.log.Error("failed to store envelope", logr.M("error", storeErr.Error()))
			writeError(w, http.StatusInternalServerError, "failed to store message")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"envelope_hash": hex.EncodeToString(hash[:])})
}
