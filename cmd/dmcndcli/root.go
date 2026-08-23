package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
)

// root.go holds what every ceremony command needs: the domain root key, and a way to talk to the
// running daemon.
//
// The root key lives HERE, on the operator's machine, and not on the node. That is the whole
// posture: a node that cannot issue is a node whose compromise cannot mint addresses. What
// crosses the wire from these commands is only signatures and public credentials — never the key.
//
// "Offline" is doing honest work in that sentence but not unlimited work: the machine running
// these commands must be able to reach the daemon, so it is offline in the sense of "not the
// internet-facing node", not air-gapped. A genuinely air-gapped root would need the signing step
// split out and the result carried across by hand; the format would support it, the CLI does not
// do it today.

// defaultRootKeystore is where domain init writes the root key, and where every other ceremony
// command looks for it. A file in the working directory, not under the daemon's data dir — those
// are different machines now, and a default that pointed at the node's data dir would invite
// exactly the mistake this design removes.
const defaultRootKeystore = "root.enc"

// rootAlias is the keystore entry holding a domain's root key. It is not a real address, so it
// cannot collide with anything else stored alongside it.
func rootAlias(domain string) string { return "__domain_root__@" + domain }

// rootFlags are the flags every ceremony command shares.
type rootFlags struct {
	keystore   *string
	passphrase *string
}

func addRootFlags(fs *flag.FlagSet) rootFlags {
	return rootFlags{
		keystore:   fs.String("keystore", envOr("DMCND_ROOT_KEYSTORE", defaultRootKeystore), "encrypted keystore holding the domain root key (on THIS machine, not the node)"),
		passphrase: fs.String("passphrase", os.Getenv("DMCND_ROOT_PASSPHRASE"), "passphrase for the root keystore"),
	}
}

// load opens the root key for domain, and says where it looked when it cannot.
func (r rootFlags) load(domain string) (*identity.IdentityKeyPair, error) {
	if *r.passphrase == "" {
		return nil, fmt.Errorf("--passphrase is required (or set DMCND_ROOT_PASSPHRASE) to open %s", *r.keystore)
	}
	kp, err := keystore.New(*r.keystore, *r.passphrase).Load(rootAlias(domain))
	if err != nil {
		return nil, fmt.Errorf("load the root key for %s from %s: %w\n"+
			"  This is the key `dmcndcli domain init` created. It is not on the node — if you are on the\n"+
			"  node right now, you are on the wrong machine.", domain, *r.keystore, err)
	}
	return kp, nil
}

// daemonClient talks to a running daemon's HTTP API.
type daemonClient struct {
	base string
	http *http.Client
}

func newDaemonClient(base string, insecure bool) (*daemonClient, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return nil, fmt.Errorf("--url is required — the daemon's webmail URL, e.g. https://mesh.example:8443")
	}
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "https://" + base
	}
	c := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		c.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &daemonClient{base: base, http: c}, nil
}

// postJSON sends a JSON request and decodes a JSON response, surfacing the daemon's own error
// message rather than a bare status code — these are operator commands and the daemon's reason is
// almost always the actionable part.
func (c *daemonClient) postJSON(path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.http.Post(c.base+path, "application/json", strings.NewReader(string(buf)))
	if err != nil {
		return fmt.Errorf("reach the daemon at %s: %w", c.base, err)
	}
	defer resp.Body.Close()

	var raw json.RawMessage
	dec := json.NewDecoder(resp.Body)
	_ = dec.Decode(&raw)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error != "" {
			return fmt.Errorf("%s: %s", resp.Status, e.Error)
		}
		return fmt.Errorf("%s from %s", resp.Status, path)
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// challenge fetches a one-shot nonce for the admin to sign with the domain root.
func (c *daemonClient) challenge() ([]byte, error) {
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := c.postJSON("/api/v1/admin/challenge", struct{}{}, &out); err != nil {
		return nil, err
	}
	return b64decode(out.Nonce)
}

func b64decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return b, nil
}

func b64encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
