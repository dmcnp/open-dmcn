package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mertenvg/logr/v2"
	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/crypto"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
)

// The mailbox gate (SPEC_EXT_DEVICES.md §3), tested where both transports meet it.

type gateFixture struct {
	r     *Relay
	kp    *identity.IdentityKeyPair
	rec   *identity.IdentityRecord
	rxHex string
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	kp, err := identity.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := identity.NewIdentityRecord("owner@example.org", kp)
	if err != nil {
		t.Fatal(err)
	}
	store := dssync.MutexWrap(ds.NewMapDatastore())
	return &gateFixture{
		r: &Relay{
			devices:    NewDeviceStore(store),
			personalKv: NewPersonalKvStore(store),
			log:        logr.With(logr.M("test", "devicegate")),
		},
		kp: kp, rec: rec, rxHex: mailboxKeyHex(rec),
	}
}

type testDevice struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestDevice(t *testing.T) testDevice {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testDevice{pub, priv}
}

// proof builds what a request brings. account and device each choose whether their half is there.
func (f *gateFixture) proof(t *testing.T, account bool, dev *testDevice) MailboxProof {
	t.Helper()
	nonce, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	p := MailboxProof{Nonce: nonce}
	if account {
		if p.Signature, err = crypto.Sign(f.kp.Ed25519Private, nonce); err != nil {
			t.Fatal(err)
		}
	}
	if dev != nil {
		p.DevicePublic = dev.pub
		if p.DeviceSignature, err = identity.SignDeviceChallenge(dev.priv, nonce); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func (f *gateFixture) enrolFirst(t *testing.T) testDevice {
	t.Helper()
	d := newTestDevice(t)
	if _, genesis, err := f.r.devices.Enroll(context.Background(), f.rxHex, d.pub, nil, false, 0, false, nil, nil); err != nil || !genesis {
		t.Fatalf("first enrolment: genesis=%v err=%v", genesis, err)
	}
	return d
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var oe *OpError
	if !errors.As(err, &oe) {
		t.Fatalf("want a refusal with code %s, got %v", code, err)
	}
	if oe.Code != code {
		t.Fatalf("want code %s, got %s (%s)", code, oe.Code, oe.Message)
	}
}

// A mailbox that has never held a device is answered on the account key alone, whatever the
// class, and never without it.
func TestGateNeverHeldADevice(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	for _, class := range []OpClass{ClassOwner, ClassDevice, ClassEnroll} {
		if _, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, true, nil), class); err != nil {
			t.Errorf("class %d: the account key alone was refused on a mailbox with no devices: %v", class, err)
		}
		_, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, false, nil), class)
		wantCode(t, err, "AUTH_FAILED")
	}
	// A device key nobody enrolled is no proof at all: without the account key it opens nothing.
	stranger := newTestDevice(t)
	_, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, false, &stranger), ClassDevice)
	wantCode(t, err, "AUTH_FAILED")
}

// Once a mailbox has a device, the two classes part ways.
func TestGateClasses(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	dev := f.enrolFirst(t)
	stranger := newTestDevice(t)

	cases := []struct {
		name    string
		account bool
		dev     *testDevice
		class   OpClass
		code    string // "" = allowed
	}{
		{"both signatures, owner op", true, &dev, ClassOwner, ""},
		{"both signatures, device op", true, &dev, ClassDevice, ""},
		{"device alone, device op", false, &dev, ClassDevice, ""},
		{"device alone, owner op", false, &dev, ClassOwner, "AUTH_FAILED"},
		{"device alone, enrolment", false, &dev, ClassEnroll, "AUTH_FAILED"},
		{"account alone, owner op", true, nil, ClassOwner, "DEVICE_NOT_ENROLLED"},
		{"account alone, device op", true, nil, ClassDevice, "DEVICE_NOT_ENROLLED"},
		{"account alone, enrolment", true, nil, ClassEnroll, ""},
		{"account and a stranger's device", true, &stranger, ClassOwner, "DEVICE_NOT_ENROLLED"},
		{"a stranger's device alone", false, &stranger, ClassDevice, "AUTH_FAILED"},
		{"nothing", false, nil, ClassDevice, "AUTH_FAILED"},
	}
	for _, c := range cases {
		got, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, c.account, c.dev), c.class)
		if c.code == "" {
			if err != nil {
				t.Errorf("%s: refused: %v", c.name, err)
			} else if c.dev != nil && !bytes.Equal(got, c.dev.pub) {
				t.Errorf("%s: the gate did not report which device signed", c.name)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: allowed, want %s", c.name, c.code)
			continue
		}
		var oe *OpError
		if !errors.As(err, &oe) || oe.Code != c.code {
			t.Errorf("%s: got %v, want %s", c.name, err, c.code)
		}
	}
}

// A signature that is present is checked even where it wasn't needed. A bad one is never ignored.
func TestGateChecksASignatureItDidNotNeed(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	dev := f.enrolFirst(t)

	p := f.proof(t, true, &dev)
	p.Signature[0] ^= 0xff
	_, err := f.r.AuthorizeMailbox(ctx, f.rec, p, ClassDevice)
	wantCode(t, err, "AUTH_FAILED")

	p = f.proof(t, true, &dev)
	p.DeviceSignature[0] ^= 0xff
	_, err = f.r.AuthorizeMailbox(ctx, f.rec, p, ClassOwner)
	wantCode(t, err, "AUTH_FAILED")
}

// The device signs the tagged nonce. A signature over the bare nonce, which is what the account
// key makes, must not pass as a device proof.
func TestGateRefusesAnUntaggedDeviceSignature(t *testing.T) {
	f := newGateFixture(t)
	dev := f.enrolFirst(t)
	p := f.proof(t, true, &dev)
	p.DeviceSignature = ed25519.Sign(dev.priv, p.Nonce)
	_, err := f.r.AuthorizeMailbox(context.Background(), f.rec, p, ClassOwner)
	wantCode(t, err, "AUTH_FAILED")
}

// Removing every device must not reopen the mailbox to the account key, and a recovery request
// inside its wait must not either.
func TestGateStaysClosedOnceEveryDeviceIsGone(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	first := f.enrolFirst(t)

	// The store refuses to retire the last active device, so write the tombstone the way a
	// restored or corrupted registry might hold it.
	rec, err := f.r.devices.Get(ctx, f.rxHex, first.pub)
	if err != nil {
		t.Fatal(err)
	}
	rec.RetiredAt = time.Now().Unix()
	putDeviceRecord(t, f.r.devices, f.rxHex, rec)

	_, err = f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, true, nil), ClassOwner)
	wantCode(t, err, "DEVICE_NOT_ENROLLED")
	_, err = f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, true, &first), ClassOwner)
	wantCode(t, err, "DEVICE_NOT_ENROLLED")

	// A device waiting out recovery is on the list and can't act.
	waiting := newTestDevice(t)
	if _, _, err := f.r.devices.Enroll(ctx, f.rxHex, waiting.pub, nil, false, time.Hour, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, err = f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, true, &waiting), ClassDevice)
	wantCode(t, err, "DEVICE_NOT_ENROLLED")
}

func putDeviceRecord(t *testing.T, s *DeviceStore, rxHex string, rec *dmcnpb.DeviceRecord) {
	t.Helper()
	data, err := proto.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.Put(context.Background(), deviceKey(rxHex, rec.Ed25519PublicKey), data); err != nil {
		t.Fatal(err)
	}
}

// A relay with no registry needs the account key every time, and ignores a device proof.
func TestGateWithoutARegistry(t *testing.T) {
	f := newGateFixture(t)
	f.r.devices = nil
	ctx := context.Background()
	dev := newTestDevice(t)
	if _, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, true, nil), ClassOwner); err != nil {
		t.Fatalf("account key refused where there is no registry: %v", err)
	}
	_, err := f.r.AuthorizeMailbox(ctx, f.rec, f.proof(t, false, &dev), ClassDevice)
	wantCode(t, err, "AUTH_FAILED")
}

// The names a device may write on its own are matched exactly.
func TestKvClasses(t *testing.T) {
	put := map[string]OpClass{
		"drafts/abc":        ClassDevice,
		"draft-body/abc":    ClassDevice,
		"draft-att/abc/1":   ClassDevice,
		"flags/abc":         ClassDevice,
		"settings/labels":   ClassDevice,
		"settings/app":      ClassOwner,
		"settings/labels/x": ClassOwner,
		"settings/labels2":  ClassOwner,
		"Flags/abc":         ClassOwner,
		"flags":             ClassOwner,
		"flags/":            ClassOwner,
		"contacts/abc":      ClassOwner,
		"sent/abc":          ClassOwner,
		"xflags/abc":        ClassOwner,
		"":                  ClassOwner,
	}
	for key, want := range put {
		if got := KvPutClass(key); got != want {
			t.Errorf("KvPutClass(%q) = %d, want %d", key, got, want)
		}
	}
	del := map[string]OpClass{
		"drafts/abc":      ClassDevice,
		"draft-body/abc":  ClassDevice,
		"draft-att/abc":   ClassDevice,
		"flags/abc":       ClassOwner, // a device may rewrite a flag record, never remove one
		"settings/labels": ClassOwner,
		"contacts/abc":    ClassOwner,
	}
	for key, want := range del {
		if got := KvDeleteClass(key); got != want {
			t.Errorf("KvDeleteClass(%q) = %d, want %d", key, got, want)
		}
	}
}

// Every op has a class, and the ones that remove mail or change who is on the mailbox are the
// owner's.
func TestMailboxOpClasses(t *testing.T) {
	cases := []struct {
		name string
		op   *dmcnpb.MailboxOp
		want OpClass
	}{
		{"list", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_List{List: &dmcnpb.MailboxListOp{}}}, ClassDevice},
		{"body", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_Body{Body: &dmcnpb.MailboxBodyOp{}}}, ClassDevice},
		{"delete", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_Delete{Delete: &dmcnpb.MailboxDeleteOp{}}}, ClassOwner},
		{"kv_get", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvGet{KvGet: &dmcnpb.MailboxKvGetOp{Key: "contacts/a"}}}, ClassDevice},
		{"kv_list", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvList{KvList: &dmcnpb.MailboxKvListOp{}}}, ClassDevice},
		{"kv_stat", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvStat{KvStat: &dmcnpb.MailboxKvStatOp{}}}, ClassDevice},
		{"kv_put flags", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvPut{KvPut: &dmcnpb.MailboxKvPutOp{Key: "flags/a"}}}, ClassDevice},
		{"kv_put contacts", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvPut{KvPut: &dmcnpb.MailboxKvPutOp{Key: "contacts/a"}}}, ClassOwner},
		{"kv_delete drafts", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvDelete{KvDelete: &dmcnpb.MailboxKvDeleteOp{Key: "drafts/a"}}}, ClassDevice},
		{"kv_delete flags", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvDelete{KvDelete: &dmcnpb.MailboxKvDeleteOp{Key: "flags/a"}}}, ClassOwner},
		{"device_enroll", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceEnroll{DeviceEnroll: &dmcnpb.MailboxDeviceEnrollOp{}}}, ClassEnroll},
		{"device_list", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceList{DeviceList: &dmcnpb.MailboxDeviceListOp{}}}, ClassOwner},
		{"device_retire", &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceRetire{DeviceRetire: &dmcnpb.MailboxDeviceRetireOp{}}}, ClassOwner},
		{"no op", &dmcnpb.MailboxOp{}, ClassOwner},
	}
	for _, c := range cases {
		if got := mailboxOpClass(c.op); got != c.want {
			t.Errorf("%s: class %d, want %d", c.name, got, c.want)
		}
	}
}

// A send made on a client's behalf follows the same rule as the mailbox.
func TestSendGate(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	envHash := bytes.Repeat([]byte{7}, 32)

	if err := f.r.AuthorizeSend(ctx, f.rec, envHash, nil, nil); err != nil {
		t.Fatalf("a mailbox with no devices could not send: %v", err)
	}
	dev := f.enrolFirst(t)
	wantCode(t, f.r.AuthorizeSend(ctx, f.rec, envHash, nil, nil), "DEVICE_NOT_ENROLLED")

	sig, _ := identity.SignDeviceSend(dev.priv, envHash)
	if err := f.r.AuthorizeSend(ctx, f.rec, envHash, dev.pub, sig); err != nil {
		t.Fatalf("an enrolled device could not send: %v", err)
	}
	// A challenge answer over the same 32 bytes is not a send proof.
	asChallenge, _ := identity.SignDeviceChallenge(dev.priv, envHash)
	wantCode(t, f.r.AuthorizeSend(ctx, f.rec, envHash, dev.pub, asChallenge), "AUTH_FAILED")
}

// Every write is stamped by the relay, and the writing device is recorded where only the owner
// can read it.
func TestKvWriteMarks(t *testing.T) {
	f := newGateFixture(t)
	ctx := context.Background()
	dev := f.enrolFirst(t)
	at := time.Unix(1_800_000_000, 0)
	f.r.personalKv.SetClock(func() time.Time { return at })

	if _, err := f.r.KvPut(ctx, f.rxHex, "flags/abc", []byte("sealed"), 0, dev.pub); err != nil {
		t.Fatal(err)
	}
	it, found, err := f.r.KvGet(ctx, f.rxHex, "flags/abc")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if it.WrittenAt != at.Unix() {
		t.Fatalf("written_at = %d, want the relay's clock %d", it.WrittenAt, at.Unix())
	}
	if bytes.Contains(it.SealedWriter, dev.pub) {
		t.Fatal("the writing device is stored in the clear")
	}
	var blob message.SealedBlob
	if err := json.Unmarshal(it.SealedWriter, &blob); err != nil {
		t.Fatalf("the writer mark is not a sealed blob: %v", err)
	}
	who, err := message.OpenSealed(&blob, f.kp.X25519Private, f.kp.X25519Public)
	if err != nil {
		t.Fatalf("the owner could not open the writer mark: %v", err)
	}
	if !bytes.Equal(who, dev.pub) {
		t.Fatal("the writer mark names a different device")
	}

	// A later write moves the time forward and replaces the mark. A list carries both.
	later := at.Add(time.Hour)
	f.r.personalKv.SetClock(func() time.Time { return later })
	if _, err := f.r.KvPut(ctx, f.rxHex, "flags/abc", []byte("sealed-2"), 0, nil); err != nil {
		t.Fatal(err)
	}
	items, _, err := f.r.KvList(ctx, f.rxHex, "flags/", 0, "", true)
	if err != nil || len(items) != 1 {
		t.Fatalf("list: %d items, err=%v", len(items), err)
	}
	if items[0].WrittenAt != later.Unix() || len(items[0].SealedWriter) != 0 {
		t.Fatalf("list item: written_at=%d writer=%d bytes, want %d and none", items[0].WrittenAt, len(items[0].SealedWriter), later.Unix())
	}
}

// --- over a real stream -------------------------------------------------------------------

type gateWire struct {
	*gateFixture
	cli *Relay
	srv peer.ID
}

func newGateWire(t *testing.T) (*gateWire, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	f := newGateFixture(t)
	lookup := func(_ context.Context, addr string) (*identity.IdentityRecord, error) {
		if addr == f.rec.Address {
			return f.rec, nil
		}
		return nil, errors.New("not found")
	}
	srv := newTestHost(t)
	t.Cleanup(func() { srv.Close() })
	cli := newTestHost(t)
	t.Cleanup(func() { cli.Close() })
	cli.Peerstore().AddAddrs(srv.ID(), srv.Addrs(), time.Hour)
	if err := cli.Connect(ctx, peer.AddrInfo{ID: srv.ID(), Addrs: srv.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	d := openMailboxDS(t, t.TempDir())
	t.Cleanup(func() { d.Close() })
	rsrv := New(srv, lookup, WithMailbox(NewMailboxStore(d)), WithPersonalKv(NewPersonalKvStore(d)), WithDeviceRegistry(NewDeviceStore(d)))
	rsrv.Start()
	t.Cleanup(rsrv.Stop)
	f.r = rsrv
	return &gateWire{gateFixture: f, cli: New(cli, lookup), srv: srv.ID()}, ctx
}

// send runs one op with the chosen halves of the proof.
func (w *gateWire) send(ctx context.Context, account bool, dev *testDevice, build func(nonce []byte) *dmcnpb.MailboxOp) (*dmcnpb.RelayResponse, error) {
	return w.cli.ClientMailboxOp(ctx, w.srv, w.rec.Address, func(nonce []byte) (*dmcnpb.MailboxOp, error) {
		op := build(nonce)
		var err error
		if account {
			if op.Signature, err = crypto.Sign(w.kp.Ed25519Private, nonce); err != nil {
				return nil, err
			}
		}
		if dev != nil {
			op.DeviceEd25519PublicKey = dev.pub
			if op.DeviceSignature, err = identity.SignDeviceChallenge(dev.priv, nonce); err != nil {
				return nil, err
			}
		}
		return op, nil
	})
}

func listOp([]byte) *dmcnpb.MailboxOp {
	return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_List{List: &dmcnpb.MailboxListOp{}}}
}

func enrolOp(dev testDevice) func([]byte) *dmcnpb.MailboxOp {
	return func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceEnroll{
			DeviceEnroll: &dmcnpb.MailboxDeviceEnrollOp{Ed25519PublicKey: dev.pub},
		}}
	}
}

// The whole life of a registry over the wire: a first device, a second approved by it, a copied
// account key shut out, a removal, and the removed key staying out.
func TestDeviceRegistryOverTheWire(t *testing.T) {
	w, ctx := newGateWire(t)

	// The relay says what it does.
	ping, err := w.cli.ClientPing(ctx, w.srv)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{CapDeviceRegistry, CapDeviceReads, CapKvWriteTime} {
		found := false
		for _, c := range ping.Capabilities {
			found = found || c == want
		}
		if !found {
			t.Errorf("the relay does not advertise %q", want)
		}
	}

	// Before any device: the account key is enough.
	if _, err := w.send(ctx, true, nil, listOp); err != nil {
		t.Fatalf("list on a mailbox with no devices: %v", err)
	}

	// The first device joins at once, and asking again is its own answer.
	first := newTestDevice(t)
	resp, err := w.send(ctx, true, nil, enrolOp(first))
	if err != nil {
		t.Fatalf("first enrolment: %v", err)
	}
	if !resp.GetMailboxDeviceEnroll().GetGenesis() {
		t.Fatal("the first enrolment did not report that it created the registry")
	}
	_, err = w.send(ctx, true, &first, enrolOp(first))
	wantCode(t, err, "DEVICE_ALREADY_ENROLLED")

	// The mailbox is now gated. The account key alone opens nothing, and a second device
	// can't let itself in.
	_, err = w.send(ctx, true, nil, listOp)
	wantCode(t, err, "DEVICE_NOT_ENROLLED")
	second := newTestDevice(t)
	_, err = w.send(ctx, true, nil, enrolOp(second))
	wantCode(t, err, "DEVICE_APPROVAL_REQUIRED")

	// The first device reads on its own signature, and can't delete on it.
	if _, err := w.send(ctx, false, &first, listOp); err != nil {
		t.Fatalf("an enrolled device could not list on its own signature: %v", err)
	}
	_, err = w.send(ctx, false, &first, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_Delete{Delete: &dmcnpb.MailboxDeleteOp{Hash: make([]byte, 32)}}}
	})
	wantCode(t, err, "AUTH_FAILED")

	// It files mail on its own signature, and the relay records that it did.
	if _, err := w.send(ctx, false, &first, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvPut{KvPut: &dmcnpb.MailboxKvPutOp{Key: "flags/m1", Sealed: []byte("x")}}}
	}); err != nil {
		t.Fatalf("a device could not write a flag record: %v", err)
	}
	_, err = w.send(ctx, false, &first, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvPut{KvPut: &dmcnpb.MailboxKvPutOp{Key: "contacts/c1", Sealed: []byte("x")}}}
	})
	wantCode(t, err, "AUTH_FAILED")
	got, err := w.send(ctx, false, &first, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_KvGet{KvGet: &dmcnpb.MailboxKvGetOp{Key: "flags/m1"}}}
	})
	if err != nil {
		t.Fatal(err)
	}
	if kv := got.GetMailboxKvGet(); kv.GetWrittenAt() == 0 || len(kv.GetSealedWriter()) == 0 {
		t.Fatalf("the stored entry carries no write marks: written_at=%d writer=%d bytes", kv.GetWrittenAt(), len(kv.GetSealedWriter()))
	}

	at := time.Now().Truncate(time.Second)
	// An approval made over some other nonce is worth nothing here.
	_, err = w.send(ctx, true, &first, func([]byte) *dmcnpb.MailboxOp {
		sig, _ := identity.SignDeviceApproval(first.priv, w.rec.Address, second.pub, bytes.Repeat([]byte{1}, 32), at)
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceEnroll{DeviceEnroll: &dmcnpb.MailboxDeviceEnrollOp{
			Ed25519PublicKey: second.pub, ApproverEd25519PublicKey: first.pub, ApproverSignature: sig, ApprovedAt: at.Unix(),
		}}}
	})
	wantCode(t, err, "AUTH_FAILED")

	// The first device approves the second, over this exchange's nonce. A third would have to
	// wait: with two devices on the mailbox, a new one can't vouch for another for a day.
	if _, err := w.send(ctx, true, &first, func(nonce []byte) *dmcnpb.MailboxOp {
		sig, _ := identity.SignDeviceApproval(first.priv, w.rec.Address, second.pub, nonce, at)
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceEnroll{DeviceEnroll: &dmcnpb.MailboxDeviceEnrollOp{
			Ed25519PublicKey: second.pub, ApproverEd25519PublicKey: first.pub, ApproverSignature: sig, ApprovedAt: at.Unix(),
		}}}
	}); err != nil {
		t.Fatalf("approved enrolment: %v", err)
	}
	// The list needs the account key as well, and shows both.
	_, err = w.send(ctx, false, &second, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceList{DeviceList: &dmcnpb.MailboxDeviceListOp{}}}
	})
	wantCode(t, err, "AUTH_FAILED")
	resp, err = w.send(ctx, true, &second, func([]byte) *dmcnpb.MailboxOp {
		return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceList{DeviceList: &dmcnpb.MailboxDeviceListOp{}}}
	})
	if err != nil || len(resp.GetMailboxDeviceList().GetDevices()) != 2 {
		t.Fatalf("device list: %d devices, err=%v", len(resp.GetMailboxDeviceList().GetDevices()), err)
	}

	// A device can't remove itself. The other one removes it, and from then on its key is
	// refused and can't enrol again.
	retire := func(signer, target testDevice) func([]byte) *dmcnpb.MailboxOp {
		return func(nonce []byte) *dmcnpb.MailboxOp {
			sig, _ := identity.SignDeviceRetirement(signer.priv, w.rec.Address, target.pub, nonce)
			return &dmcnpb.MailboxOp{Op: &dmcnpb.MailboxOp_DeviceRetire{DeviceRetire: &dmcnpb.MailboxDeviceRetireOp{
				Ed25519PublicKey: target.pub, SignerEd25519PublicKey: signer.pub, SignerSignature: sig,
			}}}
		}
	}
	_, err = w.send(ctx, true, &first, retire(first, first))
	wantCode(t, err, "INVALID_REQUEST")
	if _, err := w.send(ctx, true, &second, retire(second, first)); err != nil {
		t.Fatalf("retire: %v", err)
	}
	_, err = w.send(ctx, true, &first, listOp)
	wantCode(t, err, "DEVICE_NOT_ENROLLED")
	_, err = w.send(ctx, true, nil, enrolOp(first))
	wantCode(t, err, "DEVICE_APPROVAL_REQUIRED")
	// The last device can't be removed, even by asking as the removed one.
	_, err = w.send(ctx, true, &second, retire(first, second))
	wantCode(t, err, "AUTH_FAILED")
}

// The drain FETCH hands over every pending envelope, so a device's signature alone never gets it.
func TestFetchProofNeedsTheAccountKey(t *testing.T) {
	w, ctx := newGateWire(t)
	dev := newTestDevice(t)
	if _, err := w.send(ctx, true, nil, enrolOp(dev)); err != nil {
		t.Fatal(err)
	}
	fetch := func(account, device bool) error {
		nonce, s, err := w.cli.ClientFetchChallenge(ctx, w.srv, w.rec.Address)
		if err != nil {
			return err
		}
		defer s.Close()
		proof := &dmcnpb.FetchProof{Address: w.rec.Address, Nonce: nonce}
		if account {
			proof.Signature, _ = crypto.Sign(w.kp.Ed25519Private, nonce)
		}
		if device {
			proof.DeviceEd25519PublicKey = dev.pub
			proof.DeviceSignature, _ = identity.SignDeviceChallenge(dev.priv, nonce)
		}
		if err := writeRequest(s, &dmcnpb.RelayRequest{Request: &dmcnpb.RelayRequest_FetchProof{FetchProof: proof}}); err != nil {
			return err
		}
		resp, err := readResponse(s)
		if err != nil {
			return err
		}
		if e := resp.GetError(); e != nil {
			return &OpError{Code: e.Code, Message: e.Message}
		}
		return nil
	}
	if err := fetch(true, true); err != nil {
		t.Fatalf("FETCH with both signatures: %v", err)
	}
	wantCode(t, fetch(false, true), "AUTH_FAILED")
	wantCode(t, fetch(true, false), "DEVICE_NOT_ENROLLED")
}
