package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/core/pairing"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/relay"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/webcore"
)

// The device registry as a client meets it: over the web host's two mailbox endpoints, against
// the daemon's own node. What this pins is the contract a client codes against: the request
// fields, and the code each refusal comes back with.
func TestDeviceRegistryOverTheWebAPI(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const domain = "localhost"
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       domain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()
	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomainDev(ctx, n, domain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	const address = "bob@" + domain
	kp, err := seeds.seedIdentity(ctx, n, rootKP, address, now)
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) { return n.Lookup(ctx, addr) }

	h := webapi.NewMailboxHandler(newInProcRelay(n, lookup), logr.With(logr.M("test", "devices")))
	as := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			next(w, r.WithContext(context.WithValue(r.Context(), webcore.ContextKeyAddress, address)))
		}
	}
	post := func(handler http.HandlerFunc, body map[string]any) (int, map[string]any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		rr := httptest.NewRecorder()
		as(handler)(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
		out := map[string]any{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}
	b64 := base64.StdEncoding.EncodeToString

	type device struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	newDevice := func() *device {
		pub, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			t.Fatal(gerr)
		}
		return &device{pub, priv}
	}

	// run is one challenge and its completion. account and dev choose which halves of the proof
	// are sent. authorize, if set, makes the op's own signature over the same nonce.
	run := func(challenge map[string]any, account bool, dev *device, authorize func(nonce []byte) (sig []byte, approvedAt int64)) (int, map[string]any) {
		t.Helper()
		code, ch := post(h.HandleChallenge, challenge)
		if code != http.StatusOK {
			t.Fatalf("challenge %v: %d %v", challenge["op"], code, ch)
		}
		// A device dates an approval with this, so it has to be the server's clock.
		if at, _ := ch["server_time"].(float64); time.Now().Unix()-int64(at) < 0 || time.Now().Unix()-int64(at) > 5 {
			t.Fatalf("challenge server_time = %v, want this server's clock", ch["server_time"])
		}
		nonce, _ := base64.StdEncoding.DecodeString(ch["nonce"].(string))
		body := map[string]any{"correlation_id": ch["correlation_id"]}
		if account {
			sig, _ := crypto.Sign(kp.Ed25519Private, nonce)
			body["signature"] = b64(sig)
		}
		if dev != nil {
			sig, _ := identity.SignDeviceChallenge(dev.priv, nonce)
			body["device_public"], body["device_signature"] = b64(dev.pub), b64(sig)
		}
		if authorize != nil {
			sig, at := authorize(nonce)
			body["approver_signature"] = b64(sig)
			if at != 0 {
				body["approved_at"] = at
			}
		}
		return post(h.HandleComplete, body)
	}
	want := func(what string, code int, body map[string]any, status int, errCode string) {
		t.Helper()
		if code != status || (errCode != "" && body["code"] != errCode) {
			t.Fatalf("%s: got %d %v, want %d %q", what, code, body, status, errCode)
		}
	}
	list := map[string]any{"op": "list"}

	// No devices yet: the account key is enough.
	code, body := run(list, true, nil, nil)
	want("list before any device", code, body, http.StatusOK, "")

	// The first device creates the registry. Asking again says so by code.
	first := newDevice()
	enrol := func(d *device) map[string]any {
		return map[string]any{"op": "device_enroll", "device_public": b64(d.pub)}
	}
	code, body = run(enrol(first), true, first, nil)
	want("first enrolment", code, body, http.StatusOK, "")
	if body["genesis"] != true {
		t.Fatalf("first enrolment did not report genesis: %v", body)
	}
	code, body = run(enrol(first), true, first, nil)
	want("enrolling again", code, body, http.StatusConflict, "device_already_enrolled")

	// From here the account key alone is refused, with the code a client offers pairing on.
	code, body = run(list, true, nil, nil)
	want("list with the account key alone", code, body, http.StatusForbidden, "device_not_enrolled")
	second := newDevice()
	code, body = run(enrol(second), true, second, nil)
	want("a second device enrolling itself", code, body, http.StatusForbidden, "device_approval_required")

	// A device reads and files mail on its own signature, and nothing more.
	code, body = run(list, false, first, nil)
	want("list on the device signature alone", code, body, http.StatusOK, "")
	code, body = run(map[string]any{"op": "kv_put", "key": "flags/m1", "sealed": b64([]byte("x"))}, false, first, nil)
	want("flag write on the device signature alone", code, body, http.StatusOK, "")
	code, body = run(map[string]any{"op": "kv_put", "key": "contacts/c1", "sealed": b64([]byte("x"))}, false, first, nil)
	want("contact write on the device signature alone", code, body, http.StatusForbidden, "auth_failed")
	code, body = run(map[string]any{"op": "kv_get", "key": "flags/m1"}, false, first, nil)
	want("flag read", code, body, http.StatusOK, "")
	if at, _ := body["written_at"].(float64); at == 0 || body["sealed_writer"] == "" {
		t.Fatalf("the stored entry carries no write marks: %v", body)
	}

	// The first device approves the second, which can then list the registry.
	at := time.Now().Unix()
	code, body = run(enrol(second), true, first, func(nonce []byte) ([]byte, int64) {
		sig, _ := identity.SignDeviceApproval(first.priv, address, second.pub, nonce, time.Unix(at, 0))
		return sig, at
	})
	want("approved enrolment", code, body, http.StatusOK, "")
	code, body = run(map[string]any{"op": "device_list"}, true, second, nil)
	want("device list", code, body, http.StatusOK, "")
	if devices, _ := body["devices"].([]any); len(devices) != 2 {
		t.Fatalf("device list: %v", body)
	}

	// The second removes the first, whose key is then refused.
	code, body = run(map[string]any{"op": "device_retire", "device_public": b64(first.pub)}, true, second, func(nonce []byte) ([]byte, int64) {
		sig, _ := identity.SignDeviceRetirement(second.priv, address, first.pub, nonce)
		return sig, 0
	})
	want("retire", code, body, http.StatusOK, "")
	code, body = run(list, true, first, nil)
	want("list from a removed device", code, body, http.StatusForbidden, "device_not_enrolled")

	// Sending follows the same rule.
	gate := newSendGate(n, lookup)
	envHash := bytes.Repeat([]byte{9}, 32)
	sig, _ := crypto.Sign(kp.Ed25519Private, envHash)
	var oe *relay.OpError
	if gerr := gate(ctx, address, envHash, sig, nil, nil); gerr == nil {
		t.Fatal("a send with no device proof was allowed on a mailbox that has devices")
	} else if !asOpError(gerr, &oe) || oe.Code != "DEVICE_NOT_ENROLLED" {
		t.Fatalf("send with no device proof: %v", gerr)
	}
	proof, _ := identity.SignDeviceSend(second.priv, envHash)
	if gerr := gate(ctx, address, envHash, sig, second.pub, proof); gerr != nil {
		t.Fatalf("an enrolled device could not send: %v", gerr)
	}
}

func asOpError(err error, target **relay.OpError) bool { return errors.As(err, target) }

// Pairing against the daemon, as the two devices drive it: the newcomer publishes a throwaway
// identity and asks, a device on the account enrols the newcomer's key and answers, and the
// newcomer then opens the mailbox as a device of its own (SPEC_EXT_DEVICES.md §8).
func TestPairingAgainstTheDaemon(t *testing.T) {
	log = logr.With(logr.M("component", "dmcnd-test"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const domain = "localhost"
	n, err := node.New(ctx, node.Config{
		AllowedPeers: []string{"*"},
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		DataDir:      t.TempDir(),
		Mailbox:      true,
		Domain:       domain,
		DNSVerifier:  func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("node.New: %v", err)
	}
	defer n.Close()
	seeds := newSeedStore(t.TempDir(), "test-pass")
	now := time.Now()
	rootKP, err := seeds.seedDomainDev(ctx, n, domain, now)
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	const account = "bob@" + domain
	accountKP, err := seeds.seedIdentity(ctx, n, rootKP, account, now)
	if err != nil {
		t.Fatalf("seed bob: %v", err)
	}
	lookup := func(ctx context.Context, addr string) (*identity.IdentityRecord, error) { return n.Lookup(ctx, addr) }
	proxy := newInProcRelay(n, lookup)
	router := newInProcRouter(n)
	gate := newSendGate(n, lookup)
	sessions, err := webcore.NewSessionStore([]byte("test-session-signing-secret-32by"), time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	pair := webapi.NewPairHandler(sessions, func(ctx context.Context, rec *identity.IdentityRecord) error {
		_, perr := n.PublishIdentity(ctx, rec)
		return perr
	}, log)

	// proofFor signs a fresh challenge on address with the given halves.
	proofFor := func(address string, kp *identity.IdentityKeyPair, devPub ed25519.PublicKey, devPriv ed25519.PrivateKey) relay.MailboxProof {
		t.Helper()
		nonce, cerr := proxy.Challenge(ctx, address)
		if cerr != nil {
			t.Fatalf("challenge for %s: %v", address, cerr)
		}
		p := relay.MailboxProof{Nonce: nonce}
		if kp != nil {
			p.Signature, _ = crypto.Sign(kp.Ed25519Private, nonce)
		}
		if devPriv != nil {
			p.DevicePublic = devPub
			p.DeviceSignature, _ = identity.SignDeviceChallenge(devPriv, nonce)
		}
		return p
	}
	// send seals msg to the recipient, signs it as the sender, passes the send gate and stores it.
	send := func(msg *message.PlaintextMessage, fromAddr string, fromKP *identity.IdentityKeyPair, devPub ed25519.PublicKey, devPriv ed25519.PrivateKey, toAddr string) *message.EncryptedEnvelope {
		t.Helper()
		toRec, lerr := lookup(ctx, toAddr)
		if lerr != nil {
			t.Fatalf("lookup %s: %v", toAddr, lerr)
		}
		if len(toRec.RelayHints) == 0 {
			t.Fatalf("%s resolved with no relay hints", toAddr)
		}
		sh, content, serr := message.Split(msg, fromKP.Ed25519Private)
		if serr != nil {
			t.Fatal(serr)
		}
		env, eerr := message.EncryptSplit(sh, content, []message.RecipientInfo{{X25519Pub: toRec.X25519Public}}, fromKP.Ed25519Private)
		if eerr != nil {
			t.Fatal(eerr)
		}
		raw, _ := proto.Marshal(env.ToProto())
		envHash := crypto.SHA256Hash(raw)
		sig, _ := crypto.Sign(fromKP.Ed25519Private, envHash[:])
		var devSig []byte
		if devPriv != nil {
			devSig, _ = identity.SignDeviceSend(devPriv, envHash[:])
		}
		if gerr := gate(ctx, fromAddr, envHash[:], sig, devPub, devSig); gerr != nil {
			t.Fatalf("send gate refused %s: %v", fromAddr, gerr)
		}
		if _, serr := router.StorePreSignedOnPeer(ctx, toRec.RelayHints[0], fromAddr, sig, env); serr != nil {
			t.Fatalf("store for %s: %v", toAddr, serr)
		}
		return env
	}
	open := func(env *message.EncryptedEnvelope, kp *identity.IdentityKeyPair) *message.MessageContent {
		t.Helper()
		hdr, herr := message.DecryptHeader(env, kp.X25519Private, kp.X25519Public)
		if herr != nil {
			t.Fatalf("decrypt header: %v", herr)
		}
		mc, berr := message.DecryptBody(env, &hdr.Header, kp.X25519Private, kp.X25519Public)
		if berr != nil {
			t.Fatalf("decrypt body: %v", berr)
		}
		return mc
	}
	listCount := func(address string, p relay.MailboxProof) int {
		t.Helper()
		entries, _, lerr := proxy.List(ctx, address, p, 0, nil)
		if lerr != nil {
			t.Fatalf("list %s: %v", address, lerr)
		}
		return len(entries)
	}

	// The account already has one device: the one that will approve.
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, genesis, eerr := proxy.DeviceEnroll(ctx, account, proofFor(account, accountKP, nil, nil),
		&dmcnpb.MailboxDeviceEnrollOp{Ed25519PublicKey: oldPub}); eerr != nil || !genesis {
		t.Fatalf("first device: genesis=%v err=%v", genesis, eerr)
	}

	// 1. The newcomer makes its device key and a throwaway identity, and publishes the record
	// through the open endpoint. A real address is refused there.
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	eph, _ := identity.GenerateIdentityKeyPair()
	ephAddr, _ := pairing.EphemeralAddress()
	ephRec, err := pairing.NewEphemeralRecord(ephAddr, eph, n.RelayHints()[0], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	postJSON := func(h http.HandlerFunc, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
		return rr
	}
	recBytes, _ := proto.Marshal(ephRec.ToProto())
	if rr := postJSON(pair.HandleRegister, map[string]string{"identity_record": base64.StdEncoding.EncodeToString(recBytes)}); rr.Code != http.StatusNoContent {
		t.Fatalf("pair register: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postJSON(pair.HandleSession, map[string]string{"ephemeral_address": ephAddr}); rr.Code != http.StatusOK {
		t.Fatalf("pair session: %d %s", rr.Code, rr.Body.String())
	}
	if rr := postJSON(pair.HandleSession, map[string]string{"ephemeral_address": account}); rr.Code != http.StatusForbidden {
		t.Fatalf("a pairing session for a real address: %d, want 403", rr.Code)
	}
	realRec, _ := lookup(ctx, account)
	realBytes, _ := proto.Marshal(realRec.ToProto())
	if rr := postJSON(pair.HandleRegister, map[string]string{"identity_record": base64.StdEncoding.EncodeToString(realBytes)}); rr.Code != http.StatusForbidden {
		t.Fatalf("pair register for a real address: %d, want 403", rr.Code)
	}

	// 2. It asks: a message to the account from the throwaway identity, carrying its device key.
	reqMsg, err := pairing.BuildCloneRequestMessage(eph, ephAddr, account, "new phone")
	if err != nil {
		t.Fatal(err)
	}
	reqEnv := send(reqMsg, ephAddr, eph, nil, nil, account)
	if got := listCount(account, proofFor(account, accountKP, oldPub, oldPriv)); got != 1 {
		t.Fatalf("the account's mailbox holds %d messages, want the request", got)
	}

	// 3. The approver reads the request and checks the code the person typed in.
	request, ok := pairing.ExtractCloneRequest(open(reqEnv, accountKP))
	if !ok {
		t.Fatal("the request carries no pairing payload")
	}
	shown := pairing.ConfirmationCode(account, eph.Ed25519Public, eph.X25519Public[:])
	if got := pairing.ConfirmationCode(account, request.EphemeralEd25519Pub, request.EphemeralX25519Pub[:]); got != shown {
		t.Fatalf("confirmation code %s, the newcomer shows %s", got, shown)
	}

	// 4. It enrols the newcomer's device key, over the live challenge.
	approval := proofFor(account, accountKP, oldPub, oldPriv)
	at := time.Now().Truncate(time.Second)
	approvalSig, _ := identity.SignDeviceApproval(oldPriv, account, newPub, approval.Nonce, at)
	if _, _, eerr := proxy.DeviceEnroll(ctx, account, approval, &dmcnpb.MailboxDeviceEnrollOp{
		Ed25519PublicKey: newPub, ApproverEd25519PublicKey: oldPub, ApproverSignature: approvalSig, ApprovedAt: at.Unix(),
	}); eerr != nil {
		t.Fatalf("the approver could not enrol the newcomer: %v", eerr)
	}

	// 5. It sends the keys, sealed to the throwaway key, from an enrolled device.
	respMsg, err := pairing.BuildCloneResponseMessage(accountKP, account, ephAddr)
	if err != nil {
		t.Fatal(err)
	}
	respEnv := send(respMsg, account, accountKP, oldPub, oldPriv, ephAddr)

	// 6. The newcomer finds the answer in the throwaway mailbox, which has no devices and
	// opens on the throwaway key, and adopts the keys.
	if got := listCount(ephAddr, proofFor(ephAddr, eph, nil, nil)); got != 1 {
		t.Fatalf("the throwaway mailbox holds %d messages, want the answer", got)
	}
	response, ok := pairing.ExtractCloneResponse(open(respEnv, eph))
	if !ok {
		t.Fatal("the answer carries no key bundle")
	}
	adopted := response.KeyPair()
	if !bytes.Equal(adopted.Ed25519Public, accountKP.Ed25519Public) || adopted.X25519Private != accountKP.X25519Private {
		t.Fatal("the adopted keys are not the account's")
	}

	// The newcomer is on the mailbox: it reads with its own device key, and sends.
	if got := listCount(account, proofFor(account, adopted, newPub, newPriv)); got != 1 {
		t.Fatalf("the paired device sees %d messages", got)
	}
	// And the throwaway identity never got standing on the account.
	if _, _, lerr := proxy.List(ctx, account, proofFor(account, eph, nil, nil), 0, nil); lerr == nil {
		t.Fatal("the throwaway key opened the account's mailbox")
	}
}
