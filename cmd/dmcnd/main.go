// Binary dmcnd is the DMCN reference daemon: a single process that is a serving node
// (durable mailbox + record store + relay), the webmail backend, and — in later phases —
// the SMTP bridge and onion transport, for ONE self-hosted domain. It is the open-source
// reference implementation of the DMCN core protocol.
//
// Unlike the product's split (a relay fleet + a separate stateless web client + a provider
// funnel), dmcnd folds the mailbox node and the webmail into one binary. The webmail backend
// talks to the node in-process (a host cannot dial itself), yet stays zero-knowledge: it holds
// no user private key, and the browser signs every FETCH/STORE nonce.
package main

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"embed"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/buildinfo"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/p2plog"
	"dmcn.dev/open-dmcn/internal/petition"
	webapi "dmcn.dev/open-dmcn/internal/web/api"
	"dmcn.dev/open-dmcn/internal/web/server"
	"dmcn.dev/open-dmcn/internal/webcore"
)

//go:embed web/dist
var frontendFS embed.FS

var (
	version = "dev"
	log     logr.Logger
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println("dmcnd", buildinfo.Version(version))
		return
	}
	// peer-id has to work BEFORE the daemon can start. A live domain refuses to boot without a
	// bundle, the bundle is built on the admin's machine, and building it needs the seed
	// multiaddr — which needs this peer ID. Bare stdout so it drops into a shell substitution.
	if len(os.Args) >= 2 && os.Args[1] == "peer-id" {
		if err := printPeerID(); err != nil {
			fmt.Fprintln(os.Stderr, "dmcnd:", err)
			os.Exit(1)
		}
		return
	}

	logr.AddWriter(os.Stderr, logr.WithFormatter(logr.FormatWithColours), logr.WithFilter(logr.Verbose))
	log = logr.With(logr.M("component", "dmcnd"))
	p2plog.Silence()

	cfg := loadConfig()

	// Check we can bind the webmail port before doing anything else. Without this the failure
	// lands at the very END of startup — after the node is up, the domain adopted and the
	// authority record served — and then takes the whole daemon down with it. Same error either
	// way; the difference is whether the operator waits through a successful-looking boot first.
	if err := preflightListen(cfg.httpListen); err != nil {
		fatalf("%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The single serving node: durable mailbox + local record store + relay handlers. NOT
	// ClientOnly — this process IS the infrastructure for its domain (node.New forbids
	// ClientOnly+Mailbox and only arms the onion key for serving nodes).
	nodeCfg := node.Config{
		ListenAddr:      cfg.nodeListen,
		AnnounceAddrs:   cfg.announceAddrs,
		IdentityKeyPath: cfg.identityKeyPath,
		DataDir:         cfg.dataDir,
		Mailbox:         true,
		Domain:          cfg.domain,
		Peers:           cfg.peers,
		AllowedPeers:    cfg.allowedPeers,
	}
	// Dev mode stubs DAR DNS anchoring so a local domain with no real _dmcn TXT verifies
	// (production resolves the real record). The seed's static _dmcn still supplies the
	// fingerprint + this node's seed multiaddr.
	if cfg.devMode {
		nodeCfg.DNSVerifier = func(context.Context, string, string) error { return nil }
	}
	// Optional static _dmcn pins for OTHER domains (federation without live DNS, or an operator
	// seed-pin). The seed merges this node's own-domain anchor on top, so both coexist.
	if sd, sderr := node.LoadStaticDNS(os.Getenv("DMCND_STATIC_DNS")); sderr != nil {
		log.Warnf("DMCND_STATIC_DNS ignored: %v", sderr)
	} else if sd != nil {
		nodeCfg.StaticDNS = sd
	}

	n, err := node.New(ctx, nodeCfg)
	if err != nil {
		fatalf("failed to create node: %v", err)
	}
	defer n.Close()
	log.Infof("node up: peer ID %s, serving domain %s", n.PeerID(), cfg.domain)

	// Bring up the domain. Which branch runs decides where the domain root key lives, and that
	// is the single most consequential choice in a deployment — see cmd/dmcnd/seed.go.
	now := time.Now()
	var (
		rootKP *identity.IdentityKeyPair // dev only; nil on a live domain, deliberately
		dar    *identity.DomainAuthorityRecord
		seeds  *seedStore
	)
	if cfg.devMode {
		seeds = newSeedStore(cfg.dataDir, cfg.seedPassphrase)
		rootKP, err = seeds.seedDomainDev(ctx, n, cfg.domain, now)
		if err != nil {
			fatalf("seed domain %s: %v", cfg.domain, err)
		}
	} else {
		// The authority record is pushed here from the machine holding the root, so the node has
		// to be listening before it can be given its own domain. Nothing user-facing starts until
		// it arrives; on every restart after the first it is already in the persistent store.
		if dar, err = awaitDomainAuthority(ctx, n, cfg.domain); err != nil {
			fatalf("waiting for the domain authority record: %v", err)
		}
		if err = adoptDomain(n, dar); err != nil {
			fatalf("adopt domain %s: %v", cfg.domain, err)
		}
	}

	// The petition queue: how addresses come into existence on a live domain. Dev mode has the
	// root here and registers self-service instead, so it has no queue.
	var petitions *petition.Store
	if !cfg.devMode {
		petitions, err = petition.NewStore(filepath.Join(cfg.dataDir, "petitions.json"), cfg.petitionTTL)
		if err != nil {
			fatalf("open petition queue: %v", err)
		}
		if pending := petitions.Pending(now); pending > 0 {
			log.Infof("petition queue: %d pending (TTL %s)", pending, cfg.petitionTTL)
		}
	}

	// Optional SMTP bridge, folded onto the shared node. It has no identity of its own: it signs
	// with the node's key and is trusted through a root-signed `bridge` credential, so all the
	// daemon does here is hand it that credential and let it own the SMTP<->DMCN translation. Inbound auth runs real SPF/DKIM/DMARC by
	// default; outbound delivery defaults to the in-memory stub so a fresh install never sends live
	// mail until the operator opts in (DMCND_BRIDGE_DELIVERY_MODE=smtp).
	bridgeUp := false
	if cfg.bridgeEnabled {
		if cred, berr := bridgeCredential(n, rootKP, cfg, now); berr != nil {
			// A bridge whose verdicts nobody can verify is worse than no bridge: it would
			// relay mail and attach attestations that every recipient rejects. The daemon
			// still serves DMCN mail, so this degrades rather than refusing to boot.
			log.Errorf("SMTP bridge NOT started: %v", berr)
		} else {
			// Advertise it before serving: senders discover this node as a bridge by reading the
			// credential out of its relay descriptor, so a bridge that is running but not
			// advertised is one nobody can route to.
			n.SetDescriptorCredential(cred)
			// Advertise ourselves as the domain's bridge in the local _dmcn mirror, so this
			// daemon's own users can discover it. The operator publishes the same `bridge=`
			// token in real DNS for everyone else (`dmcndcli domain dns --bridge`).
			if aerr := anchorSelf(n, cfg.domain, domainFingerprint(dar, rootKP), true); aerr != nil {
				log.Warnf("could not advertise this node as the domain bridge: %v", aerr)
			}
			// Degrade rather than exit. DMCN mail keeps working without the bridge, and the
			// most likely failure here is binding :25 without the capability — which should
			// not take the whole domain offline.
			br, serr := startBridge(ctx, n, cred, cfg)
			if serr != nil {
				log.Errorf("SMTP bridge NOT started: %v", serr)
			} else {
				defer br.Stop()
				bridgeUp = true
			}
		}
	}

	// Sessions: stateless HS256 JWTs (persisted signing secret) + a persisted revocation
	// denylist. The daemon holds NO user key material — sessions only bind an already-proven
	// login to subsequent requests.
	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		fatalf("create data dir: %v", err)
	}
	jwtSecret, err := webcore.LoadOrCreateSecret(filepath.Join(cfg.dataDir, "jwt.secret"))
	if err != nil {
		fatalf("load session secret: %v", err)
	}
	sessionStore, err := webcore.NewSessionStore(jwtSecret, time.Hour, filepath.Join(cfg.dataDir, "revoked-tokens.json"))
	if err != nil {
		fatalf("create session store: %v", err)
	}

	// Closures the API handlers need, all backed by the local node.
	registryLookup := func(ctx context.Context, address string) (*identity.IdentityRecord, error) {
		return n.Lookup(ctx, address)
	}
	verifyManaged := func(ctx context.Context, rec *identity.IdentityRecord) (identity.VerificationTier, error) {
		return n.Registry().VerifyManagedIdentity(ctx, rec)
	}
	requiresOnion := func(ctx context.Context, rec *identity.IdentityRecord) bool {
		return n.Registry().RequiresOnion(ctx, rec)
	}
	relayHints := func(ctx context.Context, address string) ([]string, error) {
		return n.ComputeRelayHints(ctx, address, 0, nil)
	}
	replicates := func(ctx context.Context, address string) bool {
		return n.Registry().ReplicatesMailbox(ctx, address)
	}
	// Fallback STORE (no explicit recipient hint): store into this node's own mailbox in-process.
	storeLocal := func(ctx context.Context, senderAddr string, signature []byte, env *message.EncryptedEnvelope) ([32]byte, error) {
		return n.Relay().StoreLocal(ctx, senderAddr, signature, env)
	}

	// Two mutually exclusive ways an address can come into existence, chosen by where the root
	// key is. Dev holds the root, so the browser self-registers and the daemon signs immediately.
	// A live domain does not hold it, so there is simply no code path here that can mint an
	// address — the petition queue parks the request until the offline root has signed for it.
	var regHandler *webapi.RegisterHandler
	var petHandler *webapi.PetitionHandler
	if cfg.devMode {
		provision := func(ctx context.Context, rec *identity.IdentityRecord) (string, error) {
			return provisionIdentity(ctx, n, rootKP, cfg.domain, rec, time.Now())
		}
		regHandler = webapi.NewRegisterHandler(provision, log)
	} else {
		publish := func(ctx context.Context, rec *identity.IdentityRecord) error {
			_, perr := n.PublishIdentity(ctx, rec)
			return perr
		}
		petHandler = webapi.NewPetitionHandler(petitions, cfg.domain, rootPubOf(dar), n.RelayHints, publish, log)
	}

	// API handlers. Login/import prove key possession against the fleet-resolved record; the
	// daemon keeps no user directory of its own. verifyRouting is nil: a self-host signs its
	// own routing credential (with the domain root), so there is no third party to verify against.
	authHandler := webapi.NewAuthHandler(sessionStore, registryLookup, log)
	msgHandler := webapi.NewMessageHandler(storeLocal, registryLookup, newInProcRouter(n), replicates, nil, log)
	identHandler := webapi.NewIdentityHandler(registryLookup, verifyManaged, requiresOnion, relayHints, log)
	mailboxHandler := webapi.NewMailboxHandler(newInProcRelay(n, registryLookup), log)

	// HTTP server + embedded SPA.
	srv := server.New(server.Config{
		ListenAddr: cfg.httpListen,
		Domain:     cfg.webHost,
		TLSCert:    cfg.tlsCert,
		TLSKey:     cfg.tlsKey,
		DevMode:    cfg.devMode,
		DataDir:    cfg.dataDir,
	}, log)

	subFS, err := fs.Sub(frontendFS, "web/dist")
	if err != nil {
		fatalf("frontend sub-FS: %v", err)
	}
	frontendConfig := server.FrontendConfig{
		Version:        buildinfo.Version(version),
		DefaultDomain:  cfg.domain,
		Domains:        cfg.domain,
		DevMode:        cfg.devMode,
		PollIntervalMs: int(cfg.pollInterval.Milliseconds()),
		// On a live domain the register page asks for a mailbox instead of creating one.
		PetitionMode:  !cfg.devMode,
		DomainRootPub: domainRootPub(dar, rootKP),
	}
	// Outbound to the legacy email world. Wired only when this daemon actually runs a bridge:
	// without it a non-DMCN recipient stays unreachable and says so, rather than failing
	// somewhere deeper with a less useful error.
	if bridgeUp {
		resolve := func(rctx context.Context) ([32]byte, string, error) {
			ep, rerr := n.ResolveBridge(rctx, cfg.domain)
			if rerr != nil {
				return [32]byte{}, "", rerr
			}
			return ep.X25519Public, ep.Multiaddr, nil
		}
		identHandler.SetBridgeResolver(resolve)
		msgHandler.SetBridgeResolver(resolve)
	}

	authMiddleware := webcore.AuthMiddleware(sessionStore)
	srv.RegisterAPI(authHandler, msgHandler, identHandler, mailboxHandler, regHandler, petHandler, authMiddleware, subFS, frontendConfig)

	// Autocert can only work on :443. StartAutocert installs the manager's TLSConfig, which
	// answers the TLS-ALPN-01 challenge — and ACME performs that challenge against port 443, full
	// stop. On the default :8443 the daemon would come up, log "listening with autocert", and then
	// fail every TLS handshake forever, which reads as a broken binary rather than a wrong port.
	// Refuse instead, and name all three ways out.
	if cfg.tlsCert == "" && cfg.tlsKey == "" && !cfg.devMode {
		if _, port, perr := net.SplitHostPort(cfg.httpListen); perr != nil || port != "443" {
			fatalf("DMCND_LISTEN is %q, but automatic certificates need port 443 — Let's Encrypt performs "+
				"its challenge there and nowhere else, so the daemon would start and then fail every TLS "+
				"handshake.\n"+
				"  Pick one:\n"+
				"    DMCND_LISTEN=:443                       let the daemon get its own certificate\n"+
				"    DMCND_TLS_CERT=… DMCND_TLS_KEY=…        bring your own (any port, e.g. behind a proxy)\n"+
				"    DMCND_DEV=true                          local testing over plain HTTP",
				cfg.httpListen)
		}
	}

	go func() {
		var serr error
		switch {
		case cfg.tlsCert != "" && cfg.tlsKey != "":
			serr = srv.Start(cfg.tlsCert, cfg.tlsKey)
		case cfg.devMode:
			// localhost is a secure context in browsers even over plain HTTP, so WebCrypto works.
			serr = srv.Start("", "")
		default:
			// Both names: whichever the operator actually points at this node gets a cert.
			serr = srv.StartAutocert([]string{cfg.webHost, cfg.domain}, filepath.Join(cfg.dataDir, "certs"))
		}
		if serr != nil {
			log.Errorf("server error: %v", serr)
			cancel()
		}
	}()
	// Print the URL WITH its scheme, not just the port. A bare ":8080" is not something a
	// reader can paste, and it says nothing about whether TLS is on — which is the one
	// detail they need in the second before they open a browser. See defaultHTTPListen for
	// why dev and production listen on different ports.
	switch {
	case cfg.tlsCert != "" && cfg.tlsKey != "":
		log.Infof("dmcnd webmail listening on https://%s (mail for @%s)", listenURLHost(cfg.httpListen, cfg.webHost), cfg.domain)
	case cfg.devMode:
		log.Infof("dmcnd webmail listening on http://%s (mail for @%s)", listenURLHost(cfg.httpListen, "localhost"), cfg.domain)
		log.Warnf("dev mode serves PLAIN HTTP — no TLS. Open the http:// URL above explicitly; " +
			"a browser left to guess the scheme will try https:// and fail. localhost is still a " +
			"secure context, so Web Crypto works.")
	default:
		log.Infof("dmcnd webmail listening on https://%s (mail for @%s, autocert)", listenURLHost(cfg.httpListen, cfg.webHost), cfg.domain)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Infof("received signal %s, shutting down...", sig)
	case <-ctx.Done():
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Errorf("server shutdown error: %v", err)
	}
	log.Info("dmcnd stopped")
	logr.Wait()
}

// config holds the daemon's resolved runtime configuration (all from DMCND_* env vars).
type config struct {
	httpListen string
	nodeListen string
	domain     string
	// webHost is the hostname the web client is served on, for TLS and the CORS origin. It
	// defaults to domain, and differs when an operator wants addresses at the apex
	// (user@example.com) but the client on a subdomain (mail.example.com) — the ordinary email
	// arrangement. It never affects addresses, which always come from domain.
	webHost string
	// announceAddrs overrides the multiaddrs this node tells other domains to reach it at,
	// for a host whose public address is not on any local interface (a NAT'd cloud VM).
	announceAddrs   []string
	dataDir         string
	identityKeyPath string
	tlsCert         string
	tlsKey          string
	devMode         bool
	pollInterval    time.Duration
	peers           []string
	allowedPeers    []string
	seedPassphrase  string
	// bundlePath is the offline-signed domain bundle a live domain is served from. Empty is a
	// startup error outside dev mode: without it there is no DAR, and minting one here would
	// put the domain root back on the node.
	bundlePath  string
	petitionTTL time.Duration

	// SMTP bridge (opt-in). When enabled, the daemon folds an SMTP↔DMCN bridge onto its shared
	// node: inbound legacy email is signed+encrypted into DMCN mailboxes, and DMCN mail to the
	// bridge is delivered outbound over SMTP.
	bridgeEnabled    bool
	bridgeSMTPListen string
	bridgeCredential string   // path to the bridge's root-signed `bridge` credential
	bridgeAuthMode   string   // "dns" = real SPF/DKIM/DMARC on inbound, "stub" = no checks (dev only)
	bridgeDelivery   string   // "smtp" = real MX lookup + STARTTLS outbound, "stub" = in-memory (default)
	bridgeDKIMKey    string   // PEM private key path; without it outbound mail is unsigned
	bridgeDKIMSel    string   // DKIM selector (default "dmcn")
	bridgeHELO       string   // EHLO name announced to remote MTAs (defaults to webHost, then domain)
	bridgeSendIPs    []string // public addresses this bridge sends from, for the SPF/PTR guidance
	bridgeDomain     string   // the legacy email (SMTP) domain the bridge represents
}

func loadConfig() config {
	devMode := envBool("DMCND_DEV")
	c := config{
		httpListen:       envOr("DMCND_LISTEN", defaultHTTPListen(devMode)),
		nodeListen:       envOr("DMCND_NODE_LISTEN", defaultNodeListen(devMode)),
		domain:           envOr("DMCND_DOMAIN", "localhost"),
		webHost:          os.Getenv("DMCND_WEB_HOST"),
		announceAddrs:    splitList(os.Getenv("DMCND_ANNOUNCE_ADDR")),
		dataDir:          envOr("DMCND_DATA_DIR", "data"),
		identityKeyPath:  identityKeyPath(envOr("DMCND_DATA_DIR", "data")),
		tlsCert:          os.Getenv("DMCND_TLS_CERT"),
		tlsKey:           os.Getenv("DMCND_TLS_KEY"),
		devMode:          devMode,
		peers:            splitList(os.Getenv("DMCND_PEERS")),
		allowedPeers:     splitList(os.Getenv("DMCND_ALLOWED_PEERS")),
		seedPassphrase:   envOr("DMCND_SEED_PASSPHRASE", defaultSeedPassphrase),
		bundlePath:       os.Getenv("DMCND_BUNDLE"),
		bridgeEnabled:    envBool("DMCND_BRIDGE_ENABLED"),
		bridgeAuthMode:   envOr("DMCND_BRIDGE_AUTH_MODE", "dns"),
		bridgeDelivery:   envOr("DMCND_BRIDGE_DELIVERY_MODE", "stub"),
		bridgeDKIMKey:    os.Getenv("DMCND_BRIDGE_DKIM_KEY"),
		bridgeDKIMSel:    envOr("DMCND_BRIDGE_DKIM_SELECTOR", "dmcn"),
		bridgeHELO:       os.Getenv("DMCND_BRIDGE_HELO"),
		bridgeSendIPs:    splitList(os.Getenv("DMCND_BRIDGE_SEND_IPS")),
		bridgeSMTPListen: envOr("DMCND_BRIDGE_SMTP_LISTEN", defaultBridgeSMTPListen(devMode)),
		bridgeCredential: os.Getenv("DMCND_BRIDGE_CREDENTIAL"),
		bridgeDomain:     os.Getenv("DMCND_BRIDGE_DOMAIN"),
	}
	if c.bridgeDomain == "" {
		c.bridgeDomain = envOr("DMCND_DOMAIN", "localhost")
	}
	// A self-hosted node has no peers to deny, so default the allow-set open in dev; production
	// deployments set DMCND_ALLOWED_PEERS explicitly (empty ⇒ deny-by-default).
	if len(c.allowedPeers) == 0 && devMode {
		c.allowedPeers = []string{"*"}
	}
	c.petitionTTL = petition.DefaultTTL
	if v := os.Getenv("DMCND_PETITION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			log.Warnf("DMCND_PETITION_TTL %q is not a positive duration — using %s", v, petition.DefaultTTL)
		} else {
			c.petitionTTL = d
		}
	}
	if c.webHost == "" {
		c.webHost = c.domain
	}
	// The EHLO name defaults to this host, never to the OS hostname.
	//
	// SMTPSender falls back to os.Hostname() when given nothing, which on a VPS is something like
	// "ubuntu-2gb-hel1-1": not a FQDN, no A record, and no match for the PTR. Receivers penalise
	// or reject that, and forward-confirmed reverse DNS compares the PTR against exactly this
	// name. webHost is the right answer because this is one process — the host serving webmail IS
	// the host sending mail — and an operator who set it has already told us what this machine is
	// called. Falling back to the domain covers the single-name deployment.
	if c.bridgeHELO == "" {
		c.bridgeHELO = c.webHost
	}
	pi := envOr("DMCND_POLL_INTERVAL", "10s")
	d, err := time.ParseDuration(pi)
	if err != nil {
		d = 10 * time.Second
	}
	c.pollInterval = d
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := os.Getenv(key)
	return v == "true" || v == "1"
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatalf(format string, args ...any) {
	log.Errorf(format, args...)
	logr.Wait()
	os.Exit(1)
}

// applyBridgeModes selects the bridge's inbound verifier and outbound deliverer.
//
// Both used to be unreachable: the daemon never set either field, so bridge.New installed the dev
// stubs and the real DNSAuthVerifier/SMTPSender had no caller anywhere in this repo. The site said
// inbound mail was checked with SPF/DKIM/DMARC, which was simply untrue of the binary it told you
// to run — the attestation was real but the verdict inside it was a stub's.
//
// Defaults are chosen so the honest claim is also the default one: inbound verification is REAL
// (it only costs DNS lookups when mail actually arrives), while outbound delivery stays in-memory
// until the operator opts in, so installing the daemon never starts sending live mail.
func applyBridgeModes(bcfg *bridge.Config, cfg config, log logr.Logger) (*bridge.DKIMSigner, error) {
	switch cfg.bridgeAuthMode {
	case "dns":
		bcfg.AuthVerifier = bridge.NewDNSAuthVerifier()
		log.Infof("bridge inbound auth: real SPF/DKIM/DMARC")
	case "stub":
		log.Warnf("INSECURE: DMCND_BRIDGE_AUTH_MODE=stub — inbound SPF/DKIM/DMARC verification is DISABLED and the signed verdict attached to bridged mail is meaningless (dev only)")
	default:
		return nil, fmt.Errorf("invalid DMCND_BRIDGE_AUTH_MODE %q (want \"dns\" or \"stub\")", cfg.bridgeAuthMode)
	}

	// Declared out here so the caller can report the DNS records this key implies.
	var signer *bridge.DKIMSigner
	switch cfg.bridgeDelivery {
	case "smtp":
		if cfg.bridgeDKIMKey != "" {
			key, err := bridge.LoadDKIMKey(cfg.bridgeDKIMKey)
			if err != nil {
				return nil, fmt.Errorf("load DMCND_BRIDGE_DKIM_KEY: %w", err)
			}
			if signer, err = bridge.NewDKIMSigner(cfg.bridgeDomain, cfg.bridgeDKIMSel, key); err != nil {
				return nil, err
			}
			log.Infof("outbound DKIM signing enabled (d=%s s=%s)", cfg.bridgeDomain, cfg.bridgeDKIMSel)
		} else {
			log.Warnf("outbound DKIM signing DISABLED (no DMCND_BRIDGE_DKIM_KEY) — receivers will very " +
				"likely treat this mail as spam. Generate one with `dmcndcli bridge dkim-keygen`")
		}
		bcfg.Deliverer = bridge.NewSMTPSender(bridge.SMTPSenderConfig{
			HELOName: cfg.bridgeHELO,
			DKIM:     signer,
		})
		log.Infof("bridge outbound delivery: real SMTP (MX lookup + opportunistic STARTTLS)")
	case "stub":
		// Leave Deliverer nil so bridge.New installs the in-memory stub.
		log.Warnf("bridge outbound delivery: stub — DMCN→SMTP mail is captured in memory, NOT sent (set DMCND_BRIDGE_DELIVERY_MODE=smtp to send for real)")
	default:
		return nil, fmt.Errorf("invalid DMCND_BRIDGE_DELIVERY_MODE %q (want \"smtp\" or \"stub\")", cfg.bridgeDelivery)
	}
	return signer, nil
}

// listenURLHost turns a listen address into something pasteable into a browser: a bare
// ":8443" or "0.0.0.0:8443" becomes "<host>:8443", since neither is a URL a reader can click.
func listenURLHost(listen, host string) string {
	if host == "" {
		host = "localhost"
	}
	h, port, err := net.SplitHostPort(listen)
	if err != nil {
		return host + listen // e.g. a bare ":8443" that failed to split
	}
	if h == "" || h == "0.0.0.0" || h == "::" {
		h = host
	}
	return net.JoinHostPort(h, port)
}

// defaultHTTPListen picks the webmail port when DMCND_LISTEN is unset.
//
// Dev serves plain HTTP, so it defaults to :8080 rather than an HTTPS-conventional port. Serving
// cleartext on 8443 invites both the reader and the browser to assume TLS that is not on offer,
// and the resulting connection error reads as a broken daemon rather than a wrong scheme. It is
// worse for anyone also running a hosted DMCN mail client on 8443, whose browser may hold a
// cached upgrade for localhost:8443 that no amount of documentation undoes.
//
// Production defaults to :443, because that is the only port automatic certificates can work on:
// Let's Encrypt performs the TLS-ALPN-01 challenge against 443 and nowhere else. The previous
// :8443 default could never obtain a certificate — the daemon started, announced autocert, and
// then failed every handshake. Binding 443 needs privileges (setcap CAP_NET_BIND_SERVICE, or
// systemd's AmbientCapabilities); an operator terminating TLS elsewhere sets DMCND_LISTEN and
// DMCND_TLS_CERT/KEY explicitly.
func defaultHTTPListen(devMode bool) string {
	if devMode {
		return ":8080"
	}
	return ":443"
}

// defaultNodeListen picks the libp2p listen address when DMCND_NODE_LISTEN is unset.
//
// Live domains get a FIXED port. The old default was /tcp/0 — an OS-assigned ephemeral port —
// while the quickstart told operators to publish /tcp/7400 in their _dmcn seed= record. Followed
// as written that publishes permanent DNS data pointing at a port nothing is listening on, and the
// real port changes on every restart, so the failure shows up later and looks like a federation
// bug rather than a config one. A published address has to be a stable one.
//
// Dev keeps the ephemeral port: nothing is published there, and a fixed one would stop two local
// instances running side by side, which is exactly what dev mode is for.
func defaultNodeListen(devMode bool) string {
	if devMode {
		return "/ip4/0.0.0.0/tcp/0"
	}
	return "/ip4/0.0.0.0/tcp/7400"
}

// defaultBridgeSMTPListen picks the bridge's SMTP port when DMCND_BRIDGE_SMTP_LISTEN is unset.
//
// Production is :25, because that is the only port a sending mail server will ever try. The
// previous default of :2525 was convenient — no privilege needed — and silently useless: outbound
// mail worked, so the deployment looked healthy right up until someone replied and it never
// arrived. Binding 25 needs the same CAP_NET_BIND_SERVICE as :443 already does, so an operator who
// got webmail running has already done the work.
//
// Dev keeps :2525: nothing delivers to a dev instance, and requiring a capability to try the
// bridge locally would be friction for no benefit. Mirrors defaultHTTPListen.
func defaultBridgeSMTPListen(devMode bool) string {
	if devMode {
		return ":2525"
	}
	return ":25"
}

// defaultSeedPassphrase protects the DEV domain root keystore when DMCND_SEED_PASSPHRASE is unset.
//
// It no longer needs a startup warning, because it no longer protects anything on a live domain:
// the root is on the operator's machine and the bridge derives its keys from the node, so a live
// daemon never creates a keystore at all. This value is dev-only, and dev's root key is a
// throwaway for a throwaway domain.
const defaultSeedPassphrase = "dmcnd-dev-seed"
