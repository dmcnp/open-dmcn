package identity

import (
	"testing"
	"time"
)

// A holder retiring their own address must stop verifying for readers, exactly as a root tombstone
// does. This is the half of a tombstone that is safe to delegate to the key itself.
func TestOwnerSignedRemovalSuppressesAtRead(t *testing.T) {
	root := mustKP(t)
	owner := mustKP(t)
	const domain = "dmcn.me"
	const address = "alice@dmcn.me"

	dar, err := NewDomainAuthorityRecord(domain, root, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := dar.Sign(root); err != nil {
		t.Fatal(err)
	}
	rec, err := NewIdentityRecord(address, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Sign(owner); err != nil {
		t.Fatal(err)
	}

	rm, err := NewAddressRemovalRecord(domain, address, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	rm.RemovedBindings = append(rm.RemovedBindings, RemovedBinding{
		Ed25519Public: rec.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := rm.Sign(owner); err != nil {
		t.Fatal(err)
	}

	if !RemovalIsOwnerSigned(rec, rm) {
		t.Fatal("the address's own retirement should verify against its record")
	}
	if RemovalIsRootSigned(dar, rm) {
		t.Fatal("an owner-signed retirement must never read as root-signed")
	}
	if !RemovalSuppresses(rec, dar, rm) {
		t.Fatal("an owner-signed retirement must suppress")
	}

	// A retirement signed by neither the root nor the address does nothing at all.
	stranger := mustKP(t)
	forged, err := NewAddressRemovalRecord(domain, address, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	forged.RemovedBindings = append(forged.RemovedBindings, RemovedBinding{
		Ed25519Public: rec.Ed25519Public, RemovedAt: time.Now().UTC(),
	})
	if err := forged.Sign(stranger); err != nil {
		t.Fatal(err)
	}
	if RemovalSuppresses(rec, dar, forged) {
		t.Fatal("a removal signed by a stranger suppressed a binding — anyone could take an address offline")
	}
}
