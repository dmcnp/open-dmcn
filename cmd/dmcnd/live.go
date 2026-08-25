package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/node"
)

// live.go holds the parts of startup that only exist because a live domain's root key is
// somewhere else. Dev mode reaches none of it.

// printPeerID prints this node's libp2p peer ID, creating the identity key if it does not exist
// yet, and returns without starting anything.
//
// It has to work before the daemon has a domain. The operator needs this peer ID to build the
// seed multiaddr that goes into DNS and into the domain's authority record, and that record is
// signed on a different machine. Bare stdout, so it composes:
//
//	dmcndcli domain init --seed /ip4/$IP/tcp/7400/p2p/$(dmcnd peer-id)
func printPeerID() error {
	path := identityKeyPath(envOr("DMCND_DATA_DIR", "data"))
	priv, err := node.LoadOrCreateIdentityKey(path)
	if err != nil {
		return err
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("derive peer ID: %w", err)
	}
	fmt.Println(id.String())
	return nil
}

// identityKeyPath resolves the libp2p identity key location.
//
// It defaults to a file under the data dir rather than to "ephemeral". A node with no persistent
// identity gets a new peer ID on every restart, and that peer ID is embedded in the seed multiaddr
// an operator publishes in DNS — so the default would quietly invalidate the domain's own DNS
// record the first time the daemon was restarted. Dev gets the same treatment, where it costs
// nothing and means a dev node's peer ID is stable enough to allowlist.
func identityKeyPath(dataDir string) string {
	if v := os.Getenv("DMCND_IDENTITY"); v != "" {
		return v
	}
	return filepath.Join(dataDir, "node.key")
}

// awaitDomainAuthority blocks until the node holds a domain authority record for its domain,
// polling its own store and telling the operator exactly what to run.
//
// This is the bootstrap for a live domain. The root key is on another machine, so the authority
// record arrives by being pushed here — the same libp2p record push `remove-address` uses. That
// means the node has to be listening before it can be given its own domain, so there is a short
// window at first start where it is up but not authoritative.
//
// The daemon does not serve during that window: the caller holds back the webmail and petition
// surfaces until this returns. Only the record-push path is live, which is the one thing that has
// to be. After the first push the record is in the persistent store, so restarts skip all of this.
func awaitDomainAuthority(ctx context.Context, n *node.Node, domain string) (*identity.DomainAuthorityRecord, error) {
	if dar, err := n.Registry().LookupDomainAuthority(ctx, domain); err == nil && dar != nil {
		return dar, nil
	}

	log.Errorf("no domain authority record for %s — NOT serving yet.\n"+
		"  A live domain is served from an authority record signed by a root key kept OFF this\n"+
		"  machine. On the machine holding it (if there isn't one yet, `dmcndcli domain init`):\n"+
		"      dmcndcli domain publish --domain %s --peers /ip4/<this-host>/tcp/7400/p2p/%s \\\n"+
		"          --keystore root.enc\n"+
		"  That command dials THIS node, so its libp2p port must be reachable from wherever you run\n"+
		"  it — %s. Webmail and mailbox petitions stay closed until the record arrives. Waiting…\n"+
		"  (For a throwaway local instance, DMCND_DEV=true skips all of this.)",
		domain, domain, n.PeerID(), listenHint(n))

	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-tick.C:
			dar, err := n.Registry().LookupDomainAuthority(ctx, domain)
			if err == nil && dar != nil {
				return dar, nil
			}
		}
	}
}

// adoptDomain anchors the resolver at this node for a domain whose authority record it now holds.
// No root key is loaded, minted or returned — the node serves the domain and cannot issue for it.
func adoptDomain(n *node.Node, dar *identity.DomainAuthorityRecord) error {
	if err := anchorSelf(n, dar.Domain, dar.Fingerprint(), false); err != nil {
		return err
	}
	log.Infof("serving domain %s (DAR fp %s, %d reserved local-part(s), countersign %v)",
		dar.Domain, dar.Fingerprint(), len(dar.ReservedLocalParts), dar.RequiresCountersign())
	log.Infof("the domain root key is NOT on this machine — new addresses are assigned with " +
		"`dmcndcli petition assign` from wherever it is kept")
	return nil
}

// rootPubOf returns the domain's current root public key, for verifying operator calls.
func rootPubOf(dar *identity.DomainAuthorityRecord) func() ed25519.PublicKey {
	return func() ed25519.PublicKey {
		pub, _ := dar.RootKeyAt(time.Now())
		return pub
	}
}

// bridgeCredential gets the bridge the credential that makes its verdicts believable.
//
// A bridge has no DMCN email address and no directory entry — it is a peer whose domain root has
// signed a credential saying "this key may act as a bridge for this domain". So provisioning it is
// not an account ceremony: it is one signature over the node's own public key, which the operator
// can produce offline from the peer ID alone (`dmcndcli bridge issue`).
//
// Dev signs it in-process with the local root, because dev has one and the whole point of dev is
// that nothing is a ceremony.
func bridgeCredential(n *node.Node, rootKP *identity.IdentityKeyPair, cfg config, now time.Time) (*identity.Credential, error) {
	kp, err := bridgeInfraKeys(n)
	if err != nil {
		return nil, err
	}
	if cfg.devMode {
		cred := &identity.Credential{
			Version:  1,
			Subject:  kp.Ed25519Public,
			Domain:   cfg.domain,
			Roles:    []string{identity.RoleBridge},
			IssuedAt: now.UTC(),
		}
		if serr := cred.Sign(rootKP); serr != nil {
			return nil, fmt.Errorf("sign the dev bridge credential: %w", serr)
		}
		return cred, nil
	}
	if cfg.bridgeCredential == "" {
		return nil, fmt.Errorf("no bridge credential: set DMCND_BRIDGE_CREDENTIAL.\n"+
			"  A bridge is trusted through a credential signed by the domain root, not through a\n"+
			"  mailbox. On the machine holding the root:\n"+
			"      dmcndcli bridge issue --domain %s --peer-id %s --keystore root.enc --out bridge.cred\n"+
			"  then copy bridge.cred here (it holds no private key) and point DMCND_BRIDGE_CREDENTIAL at it.",
			cfg.domain, n.PeerID())
	}
	cred, _, err := node.LoadCredentialBundle(cfg.bridgeCredential)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", cfg.bridgeCredential, err)
	}
	if cred == nil {
		return nil, fmt.Errorf("%s does not exist", cfg.bridgeCredential)
	}
	return cred, nil
}

// startBridge builds and starts the SMTP bridge around an already-provisioned identity.
func startBridge(ctx context.Context, n *node.Node, cred *identity.Credential, cfg config) (*bridge.Bridge, error) {
	bridgeKP, err := bridgeInfraKeys(n)
	if err != nil {
		return nil, err
	}
	bcfg := bridge.Config{
		SMTPListenAddr: cfg.bridgeSMTPListen,
		// The bridge's "address" is its peer ID — informational only. It has no mailbox.
		BridgeAddress: n.PeerID().String(),
		Credential:    cred,
		BridgeDomain:  cfg.bridgeDomain,
		DMCNDomain:    cfg.domain,
		AuditLogPath:  os.Getenv("DMCND_BRIDGE_AUDIT_LOG"),
	}
	signer, err := applyBridgeModes(&bcfg, cfg, log)
	if err != nil {
		return nil, err
	}
	// Print the records an operator has to publish for outbound mail to be accepted anywhere.
	// Only when actually sending: on the default stub deliverer nothing leaves the process, so
	// this would be noise. DeliverabilityDNS existed in this tree with no caller at all, which
	// meant the one thing a new bridge operator most needs was never shown to them.
	if cfg.bridgeDelivery == "smtp" {
		fmt.Fprint(os.Stderr, "\n"+bridge.DeliverabilityDNS(cfg.bridgeDomain, cfg.bridgeDKIMSel, signer, cfg.bridgeHELO, cfg.bridgeSendIPs)+"\n")
	}
	br, berr := bridge.New(ctx, n, bridgeKP, bcfg, log)
	if berr != nil {
		return nil, fmt.Errorf("start bridge: %w", berr)
	}
	if serr := br.Start(); serr != nil {
		return nil, fmt.Errorf("start bridge SMTP: %w", serr)
	}
	log.Infof("SMTP bridge folded in: listening on %s (bridge domain %s ↔ dmcn domain %s)",
		cfg.bridgeSMTPListen, cfg.bridgeDomain, cfg.domain)
	warnIfUnreachableMX(cfg)
	return br, nil
}

// warnIfUnreachableMX flags the default that silently breaks inbound mail.
//
// Production defaults to :25 now, so this fires only when an operator has deliberately moved it.
// It stays because the failure is invisible from inside: sending mail servers connect to port 25
// and nothing else, outbound is unaffected, and the deployment looks healthy right up until
// someone replies and it never arrives — with nothing in the log, because the connection was never
// made to this process.
//
// A warning rather than a refusal: forwarding 25→2525 (iptables, a systemd socket, a proxy) is a
// legitimate way to avoid granting the binary CAP_NET_BIND_SERVICE, and the daemon cannot tell
// that from a misconfiguration.
func warnIfUnreachableMX(cfg config) {
	if !mxUnreachable(cfg) {
		return
	}
	log.Warnf("the bridge is listening on %s, not port 25 — sending mail servers only ever connect "+
		"to 25, so INBOUND mail will not arrive. Outbound is unaffected, which is what makes this "+
		"easy to miss. Either set DMCND_BRIDGE_SMTP_LISTEN=:25 (needs CAP_NET_BIND_SERVICE, as :443 "+
		"does) or forward 25 to %s at the host. Also publish an MX for %s pointing at %s — "+
		"`dmcndcli bridge dkim-keygen` prints it.",
		cfg.bridgeSMTPListen, cfg.bridgeSMTPListen, cfg.bridgeDomain, cfg.bridgeHELO)
}

// mxUnreachable reports whether the bridge is listening somewhere no sending mail server will
// look. Dev is exempt: nothing is expected to deliver to it.
func mxUnreachable(cfg config) bool {
	if cfg.devMode {
		return false
	}
	_, port, err := net.SplitHostPort(cfg.bridgeSMTPListen)
	return err != nil || port != "25"
}

// domainRootPub is the domain root's public key, base64, for the SPA to verify bridge credentials
// against. Public by construction: it is what the _dmcn fingerprint commits to.
//
// It comes from the authority record on a live domain and from the local root in dev, so the
// browser does the same check in both modes rather than only in the mode nobody tests.
func domainRootPub(dar *identity.DomainAuthorityRecord, rootKP *identity.IdentityKeyPair) string {
	var pub ed25519.PublicKey
	switch {
	case dar != nil:
		pub, _ = dar.RootKeyAt(time.Now())
	case rootKP != nil:
		pub = rootKP.Ed25519Public
	}
	if len(pub) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// domainFingerprint is the domain's DAR fingerprint, from whichever half of the split holds it:
// the adopted authority record on a live domain, the local root in dev.
func domainFingerprint(dar *identity.DomainAuthorityRecord, rootKP *identity.IdentityKeyPair) string {
	if dar != nil {
		return dar.Fingerprint()
	}
	if rootKP == nil {
		return ""
	}
	d, err := identity.NewDomainAuthorityRecord("", rootKP, rootKP.CreatedAt.UTC())
	if err != nil {
		return ""
	}
	return d.Fingerprint()
}

// listenHint describes where this node is actually listening, for the "open the port" advice. The
// address an operator needs to reach is not necessarily the one in their config — a container or a
// cloud NAT can rewrite it — so report what the host bound rather than what was requested.
func listenHint(n *node.Node) string {
	addrs := n.Addrs()
	if len(addrs) == 0 {
		return "it is not listening on any address"
	}
	return "listening on " + strings.Join(addrs, ", ")
}

// preflightListen reports whether the webmail listen address can actually be bound, translating
// the two failures that actually happen into something an operator can act on.
//
// Port 443 is the default outside dev mode because automatic certificates only work there, and
// binding it needs a privilege an ordinary service user does not have. That is a reasonable
// trade — but "bind: permission denied" arriving after a clean-looking startup is not, so it is
// caught here and explained.
//
// The listener is closed again immediately, which leaves a moment in which something else could
// take the port. That is fine: the real bind still fails if so, just with the "in use" message
// this function would have given anyway.
func preflightListen(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err == nil {
		return l.Close()
	}
	return explainListenError(addr, err)
}

// explainListenError turns a bind failure into operator-facing advice. Split out from
// preflightListen so each message can be tested — the permission case in particular is
// unreproducible on a machine where unprivileged ports are unrestricted, which includes most
// containers, so it would otherwise only ever be exercised in production.
func explainListenError(addr string, err error) error {
	switch {
	case errors.Is(err, os.ErrPermission), strings.Contains(err.Error(), "permission denied"):
		return fmt.Errorf("cannot bind %s: permission denied.\n"+
			"  Ports below 1024 need a privilege this process does not have. Pick one:\n"+
			"    sudo setcap CAP_NET_BIND_SERVICE=+eip $(command -v dmcnd)   # grant it to the binary\n"+
			"    AmbientCapabilities=CAP_NET_BIND_SERVICE                    # in the systemd unit\n"+
			"    DMCND_LISTEN=:8443 DMCND_TLS_CERT=… DMCND_TLS_KEY=…         # high port, your own cert\n"+
			"  The default is :443 because automatic certificates only work there — Let's Encrypt\n"+
			"  performs its challenge against 443 and nowhere else. Moving to a high port therefore\n"+
			"  means bringing your own certificate, typically with a reverse proxy in front.",
			addr)
	case strings.Contains(err.Error(), "address already in use"):
		return fmt.Errorf("cannot bind %s: already in use.\n"+
			"  Something else is on that port — another dmcnd, or a web server. `ss -lntp | grep %s`\n"+
			"  will name it.", addr, addr)
	default:
		return fmt.Errorf("cannot bind %s: %w", addr, err)
	}
}
