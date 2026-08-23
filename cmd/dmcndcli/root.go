package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/term"
	"strings"
	"time"

	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/keystore"
	"dmcn.dev/open-dmcn/internal/node"
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
		passphrase: fs.String("passphrase", os.Getenv("DMCND_ROOT_PASSPHRASE"), "passphrase for the root keystore (prompted for if omitted; a flag leaks it to shell history and ps)"),
	}
}

// load opens the root key for domain, and says where it looked when it cannot.
func (r rootFlags) load(domain string) (*identity.IdentityKeyPair, error) {
	pass, err := r.resolvePassphrase(false)
	if err != nil {
		return nil, err
	}
	kp, err := keystore.New(*r.keystore, pass).Load(rootAlias(domain))
	if err != nil {
		return nil, fmt.Errorf("load the root key for %s from %s: %w\n"+
			"  This is the key `dmcndcli domain init` created. It is not on the node — if you are on the\n"+
			"  node right now, you are on the wrong machine.", domain, *r.keystore, err)
	}
	return kp, nil
}

// resolvePassphrase returns the keystore passphrase, prompting for it when it was not supplied.
//
// Prompting is the DEFAULT rather than a fallback, and deliberately so: this passphrase protects a
// domain's root key, and --passphrase puts its value in argv, where any other user on the machine
// can read it with ps for as long as the command runs — and in shell history besides.
//
// Both non-interactive routes stay supported, because ceremonies do get scripted. Of the two,
// DMCND_ROOT_PASSPHRASE is the better one: a scripted caller has to put the secret somewhere, and
// the environment is not argv.
//
// confirm asks twice, for a passphrase being SET rather than entered. A typo there is unrecoverable
// in the strongest sense — nothing on the domain can ever be issued or rotated again.
func (r rootFlags) resolvePassphrase(confirm bool) (string, error) {
	if *r.passphrase != "" {
		return *r.passphrase, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no passphrase for %s: pass --passphrase, set DMCND_ROOT_PASSPHRASE, or run this from a terminal so it can be typed in", *r.keystore)
	}

	pass, err := promptSecret(fmt.Sprintf("Passphrase for %s: ", *r.keystore))
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("empty passphrase")
	}
	if confirm {
		again, cerr := promptSecret("Confirm passphrase: ")
		if cerr != nil {
			return "", cerr
		}
		if again != pass {
			return "", fmt.Errorf("the two passphrases do not match")
		}
	}
	return pass, nil
}

// promptSecret reads a line from the terminal without echoing it.
func promptSecret(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
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

// dialDaemon starts an ephemeral client node and connects it to the running daemon.
//
// The failure here is worth spelling out. "timed out waiting for mesh peers" is accurate and
// tells an operator nothing: the overwhelmingly common cause is that the libp2p port is closed on
// the node — which, in the setup sequence, is a mistake made several steps before the command that
// surfaces it. Naming the address actually tried, and the three things that are usually wrong,
// turns a dead end into a next step.
func dialDaemon(ctx context.Context, peers string) (*node.Node, error) {
	list := splitCSV(peers)
	if len(list) == 0 {
		return nil, fmt.Errorf("--peers is empty")
	}
	n, err := node.New(ctx, node.Config{
		ListenAddr:   "/ip4/127.0.0.1/tcp/0",
		AllowedPeers: []string{"*"},
		ClientOnly:   true,
		Peers:        list,
	})
	if err != nil {
		return nil, fmt.Errorf("start client node: %w", err)
	}
	if err := n.WaitForPeers(ctx, 15*time.Second); err != nil {
		n.Close()
		return nil, fmt.Errorf("could not reach the daemon at %s.\n"+
			"  Most often one of:\n"+
			"    - the libp2p port (7400 by default) is not open to this machine — check the node's\n"+
			"      firewall and any cloud security group; `nc -z <host> 7400` from here should succeed\n"+
			"    - the daemon is not running, or is still waiting for its authority record\n"+
			"    - the multiaddr is wrong: it must be /ip4/<host>/tcp/<port>/p2p/<peer-id>, and the\n"+
			"      peer ID must match `dmcnd peer-id` on the node\n"+
			"  (%v)", strings.Join(list, ", "), err)
	}
	return n, nil
}
