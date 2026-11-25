package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/relay"
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
	// resolveBridge routes mail bound for the legacy email world. Optional: nil means this
	// deployment has no bridge and legacy recipients are simply unreachable.
	resolveBridge BridgeResolver
	relayRouter   RelayRouter
	// replicates reports whether the recipient's domain declares mailbox replication
	// (DAR PolicyReplicateMailbox). nil ⇒ always failover.
	replicates func(ctx context.Context, address string) bool
	// verifyRouting checks the recipient's RelayHints are attested by a verified operator
	// routing credential before we STORE to them (defeats forged-routing mail redirection).
	// nil ⇒ skipped (tests / a self-host node that signs its own routing).
	verifyRouting func(ctx context.Context, rec *identity.IdentityRecord) error
	// sendGate decides whether this send comes from a device the sender's mailbox has
	// enrolled (SPEC_EXT_DEVICES.md §9). nil ⇒ no registry behind this handler.
	sendGate SendGate
	log      logr.Logger
}

// SendGate checks a send against the sender's device registry. signature is the sender's own
// over the envelope hash; devicePub and deviceSig are the device's send proof over the same
// hash, and may be empty. It returns a *relay.OpError where the send is refused.
type SendGate func(ctx context.Context, senderAddr string, envHash, signature, devicePub, deviceSig []byte) error

// SetSendGate installs the device check for sends. Without one, sending is not gated.
func (h *MessageHandler) SetSendGate(g SendGate) { h.sendGate = g }

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
	// DevicePublic and DeviceSignature (base64) are the sending device's proof: its signature
	// over "dmcn-device-send-v1\0" || envelope hash. Needed once the sender's mailbox has
	// devices.
	DevicePublic    string `json:"device_public,omitempty"`
	DeviceSignature string `json:"device_signature,omitempty"`
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

	// The same device check that guards reading guards sending through this server. It runs
	// before anything is delivered, and says nothing about a STORE made some other way.
	if h.sendGate != nil {
		devicePub, derr := base64.StdEncoding.DecodeString(req.DevicePublic)
		deviceSig, serr := base64.StdEncoding.DecodeString(req.DeviceSignature)
		if derr != nil || serr != nil {
			writeError(w, http.StatusBadRequest, "invalid device proof encoding")
			return
		}
		canonical, merr := proto.Marshal(env.ToProto()) // as the relay hashes it
		if merr != nil {
			writeError(w, http.StatusBadRequest, "invalid envelope")
			return
		}
		envHash := crypto.SHA256Hash(canonical)
		if gerr := h.sendGate(r.Context(), req.SenderAddress, envHash[:], sigBytes, devicePub, deviceSig); gerr != nil {
			var oe *relay.OpError
			if errors.As(gerr, &oe) && oe.Code == "DEVICE_NOT_ENROLLED" {
				writeErrorCode(w, http.StatusForbidden, "device_not_enrolled",
					"This device is not approved to send from this account. Pair it from a device that still has access.")
				return
			}
			h.log.Warn("send refused at the device gate", logr.M("sender", req.SenderAddress), logr.M("error", gerr.Error()))
			writeErrorCode(w, http.StatusForbidden, "auth_failed", "this send could not be verified")
			return
		}
	}

	// Route STORE to recipient's relay hints if recipient_address is provided.
	var hash [32]byte
	if req.RecipientAddress != "" && h.registryLookup != nil && h.relayRouter != nil {
		legacy := false
		recipientRec, lookupErr := h.registryLookup(r.Context(), req.RecipientAddress)
		if lookupErr != nil {
			// Not a DMCN identity — try this domain's bridge, which is how mail reaches the
			// legacy email world. The client has already sealed the envelope to the bridge's
			// key (it got that from the same lookup), so all that is needed here is somewhere
			// to STORE it.
			bridgeRec, berr := h.legacyRecipient(r.Context(), req.RecipientAddress)
			if berr != nil {
				writeError(w, http.StatusBadRequest, "recipient not found")
				return
			}
			recipientRec, legacy = bridgeRec, true
		}
		if len(recipientRec.RelayHints) == 0 {
			writeError(w, http.StatusBadRequest, "recipient has no relay hints")
			return
		}
		// Routing integrity: the hints are operator-owned and unsigned by the owner, so verify
		// they are attested by a routing credential that chains to the domain DAR before we STORE
		// to them — otherwise a forged record could redirect this mail to attacker relays.
		//
		// Skipped for a legacy recipient, and not as a relaxation: there is no owner record to
		// carry a routing credential, and the bridge those hints point at was already
		// credential-verified during discovery — a stricter check, since it proves the peer may
		// act as a bridge for this domain rather than merely that a record was well-formed.
		if h.verifyRouting != nil && !legacy {
			if err := h.verifyRouting(r.Context(), recipientRec); err != nil {
				h.log.Warn("recipient routing verification failed", logr.M("recipient", req.RecipientAddress), logr.M("error", err.Error()))
				writeError(w, http.StatusBadGateway, "recipient routing could not be verified")
				return
			}
		}

		// Onion-route when the sender opts in or the recipient requires it. No
		// silent downgrade: if onion is requested/required and fails, the send fails.
		if (req.Onion || recipientRec.RequireOnion) && !legacy {
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
					// A closed account is the same kind of verdict; 410 lets the client say so.
					if errors.Is(serr, ErrRecipientClosed) && stored == 0 {
						h.log.Info("recipient account closed", logr.M("recipient", req.RecipientAddress))
						writeError(w, http.StatusGone, "recipient account is closed")
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

// legacyRecipient builds the routing record for an address that is not a DMCN identity: this
// domain's outbound bridge. It is synthetic and never published — it exists only to carry the
// bridge's hint through the same STORE path every other recipient uses.
func (h *MessageHandler) legacyRecipient(ctx context.Context, address string) (*identity.IdentityRecord, error) {
	if h.resolveBridge == nil {
		return nil, fmt.Errorf("no bridge configured, so %s is unreachable", address)
	}
	xPub, ma, err := h.resolveBridge(ctx)
	if err != nil {
		return nil, err
	}
	return &identity.IdentityRecord{
		Address:      address,
		X25519Public: xPub,
		RelayHints:   []string{ma},
	}, nil
}

// SetBridgeResolver installs the outbound-bridge resolver — see IdentityHandler.SetBridgeResolver
// for why this is wired after construction.
func (h *MessageHandler) SetBridgeResolver(f BridgeResolver) { h.resolveBridge = f }
