package node

import (
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"dmcn.dev/open-dmcn/dmcnpb"
	"dmcn.dev/open-dmcn/internal/core/identity"
)

// NOTE (open-dmcn reference implementation): the remote node-provisioning protocol
// (/dmcn/provision) is a PRODUCT/operator surface and is omitted. A reference node is
// either seeded with a credential bundle at boot or runs bare as its own domain's
// authority. What remains here is the credential accessors + the on-disk {credential, DAR}
// bundle format — serialized as a core dmcnpb.CredentialBundle (the message /dmcn/join uses).

// credentialFile is where a credentialed node persists its bundle so it reloads on restart.
const credentialFile = "credential.bin"

// CredentialBundle pairs a credential with the DAR that anchors it — the unit a node presents
// at /dmcn/join and loads from a credential file. A node credentialed in several domains holds
// one per domain.
type CredentialBundle struct {
	Credential *identity.Credential
	DAR        *identity.DomainAuthorityRecord
}

// IsCredentialed reports whether the node holds a membership credential (credential mode).
func (n *Node) IsCredentialed() bool {
	n.credMu.Lock()
	defer n.credMu.Unlock()
	return n.credential != nil
}

// Credential returns the node's own membership credential (the one it presents at
// /dmcn/join), or nil if it holds none.
func (n *Node) Credential() *identity.Credential {
	n.credMu.Lock()
	defer n.credMu.Unlock()
	return n.credential
}

// persistCredential writes {credential, DAR} to <DataDir>/credential.bin so the node
// reloads it on restart. No-op without a DataDir (ephemeral / dev).
func (n *Node) persistCredential(cred *identity.Credential, dar *identity.DomainAuthorityRecord) error {
	dir := n.dataDir
	if dir == "" {
		return nil
	}
	data, err := MarshalCredentialBundle(cred, dar)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, credentialFile), data, 0o600)
}

// MarshalCredentialBundle serializes {credential, DAR} into the credential.bin format
// (a core dmcnpb.CredentialBundle). A fleet credential (which chains to a config operator
// root and carries no DAR) is written with an empty Dar; domain credentials carry their DAR.
func MarshalCredentialBundle(cred *identity.Credential, dar *identity.DomainAuthorityRecord) ([]byte, error) {
	if cred == nil {
		return nil, fmt.Errorf("node: nil credential")
	}
	pb := &dmcnpb.CredentialBundle{Credential: cred.ToProto()}
	if dar != nil {
		pb.Dar = dar.ToProto()
	}
	return proto.Marshal(pb)
}

// LoadCredentialBundle reads a persisted {credential, DAR} from a credential.bin path, for
// the caller (main) to seed node.Config. Returns (nil, nil, nil) if absent.
func LoadCredentialBundle(path string) (*identity.Credential, *identity.DomainAuthorityRecord, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var bundle dmcnpb.CredentialBundle
	if err := proto.Unmarshal(data, &bundle); err != nil {
		return nil, nil, fmt.Errorf("node: credential bundle: %w", err)
	}
	cred, err := identity.CredentialFromProto(bundle.Credential)
	if err != nil {
		return nil, nil, err
	}
	// A fleet credential bundle has no DAR (it chains to the config operator root).
	var dar *identity.DomainAuthorityRecord
	if bundle.Dar != nil {
		if dar, err = identity.DomainAuthorityRecordFromProto(bundle.Dar); err != nil {
			return nil, nil, err
		}
	}
	return cred, dar, nil
}

// CredentialFilePath returns the conventional persisted-credential path under a DataDir.
func CredentialFilePath(dataDir string) string { return filepath.Join(dataDir, credentialFile) }
