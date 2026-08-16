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
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"embed"

	"github.com/mertenvg/logr/v2"

	"dmcn.dev/open-dmcn/internal/bridge"
	"dmcn.dev/open-dmcn/internal/core/identity"
	"dmcn.dev/open-dmcn/internal/core/message"
	"dmcn.dev/open-dmcn/internal/node"
	"dmcn.dev/open-dmcn/internal/p2plog"
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
		fmt.Println("dmcnd", version)
		return
	}

	logr.AddWriter(os.Stderr, logr.WithFormatter(logr.FormatWithColours), logr.WithFilter(logr.Verbose))
	log = logr.With(logr.M("component", "dmcnd"))
	p2plog.Silence()

	cfg := loadConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The single serving node: durable mailbox + local record store + relay handlers. NOT
	// ClientOnly — this process IS the infrastructure for its domain (node.New forbids
	// ClientOnly+Mailbox and only arms the onion key for serving nodes).
	nodeCfg := node.Config{
		ListenAddr:      cfg.nodeListen,
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

	// Seed the domain: root key + DAR + the static _dmcn anchor pointing the resolver here.
	// ONLY the domain's own operator keys are minted here. Accounts are created in the
	// browser at /register, which generates the keypair client-side and sends only the
	// signed public record — so the daemon never holds an account private key.
	seeds := newSeedStore(cfg.dataDir, cfg.seedPassphrase)
	now := time.Now()
	rootKP, err := seeds.seedDomain(ctx, n, cfg.domain, now)
	if err != nil {
		fatalf("seed domain %s: %v", cfg.domain, err)
	}

	// Optional SMTP bridge, folded onto the shared node. The daemon provisions the bridge's DMCN
	// identity (BridgeCapability + routing credential), then hands the node + key pair to the
	// bridge, which owns only the SMTP<->DMCN translation. Auth + delivery default to dev stubs
	// (no live mail sent); real SPF/DKIM/DMARC + outbound SMTP are deployment opt-ins.
	if cfg.bridgeEnabled {
		bridgeKP, berr := seeds.seedBridgeIdentity(ctx, n, rootKP, cfg.bridgeAddress, now)
		if berr != nil {
			fatalf("seed bridge identity %s: %v", cfg.bridgeAddress, berr)
		}
		br, berr := bridge.New(ctx, n, bridgeKP, bridge.Config{
			SMTPListenAddr: cfg.bridgeSMTPListen,
			BridgeAddress:  cfg.bridgeAddress,
			BridgeDomain:   cfg.bridgeDomain,
			DMCNDomain:     cfg.domain,
			AuditLogPath:   os.Getenv("DMCND_BRIDGE_AUDIT_LOG"),
		}, log)
		if berr != nil {
			fatalf("start bridge: %v", berr)
		}
		if berr := br.Start(); berr != nil {
			fatalf("start bridge SMTP: %v", berr)
		}
		defer br.Stop()
		log.Infof("SMTP bridge folded in: %s listening on %s (bridge domain %s ↔ dmcn domain %s)",
			cfg.bridgeAddress, cfg.bridgeSMTPListen, cfg.bridgeDomain, cfg.domain)
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

	// Self-service registration: the browser generates keys and self-signs an IdentityRecord;
	// the daemon (operator) attaches a root-signed routing credential and publishes it — the same
	// operator step as the boot seed, just for a browser-provided record. Zero-knowledge holds: the
	// daemon only ever sees the signed public record.
	provision := func(ctx context.Context, rec *identity.IdentityRecord) (string, error) {
		return provisionIdentity(ctx, n, rootKP, cfg.domain, rec, time.Now())
	}

	// API handlers. Login/import prove key possession against the fleet-resolved record; the
	// daemon keeps no user directory of its own. verifyRouting is nil: a self-host signs its
	// own routing credential (with the domain root), so there is no third party to verify against.
	authHandler := webapi.NewAuthHandler(sessionStore, registryLookup, log)
	msgHandler := webapi.NewMessageHandler(storeLocal, registryLookup, newInProcRouter(n), replicates, nil, log)
	identHandler := webapi.NewIdentityHandler(registryLookup, verifyManaged, requiresOnion, relayHints, log)
	mailboxHandler := webapi.NewMailboxHandler(newInProcRelay(n, registryLookup), log)
	regHandler := webapi.NewRegisterHandler(provision, log)

	// HTTP server + embedded SPA.
	srv := server.New(server.Config{
		ListenAddr: cfg.httpListen,
		Domain:     cfg.domain,
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
		Version:        version,
		DefaultDomain:  cfg.domain,
		Domains:        cfg.domain,
		DevMode:        cfg.devMode,
		PollIntervalMs: int(cfg.pollInterval.Milliseconds()),
	}
	authMiddleware := webcore.AuthMiddleware(sessionStore)
	srv.RegisterAPI(authHandler, msgHandler, identHandler, mailboxHandler, regHandler, authMiddleware, subFS, frontendConfig)

	go func() {
		var serr error
		switch {
		case cfg.tlsCert != "" && cfg.tlsKey != "":
			serr = srv.Start(cfg.tlsCert, cfg.tlsKey)
		case cfg.devMode:
			// localhost is a secure context in browsers even over plain HTTP, so WebCrypto works.
			serr = srv.Start("", "")
		default:
			serr = srv.StartAutocert(cfg.domain, filepath.Join(cfg.dataDir, "certs"))
		}
		if serr != nil {
			log.Errorf("server error: %v", serr)
			cancel()
		}
	}()
	log.Infof("dmcnd webmail listening on %s (domain %s)", cfg.httpListen, cfg.domain)

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
	httpListen      string
	nodeListen      string
	domain          string
	dataDir         string
	identityKeyPath string
	tlsCert         string
	tlsKey          string
	devMode         bool
	pollInterval    time.Duration
	peers           []string
	allowedPeers    []string
	seedPassphrase  string

	// SMTP bridge (opt-in). When enabled, the daemon folds an SMTP↔DMCN bridge onto its shared
	// node: inbound legacy email is signed+encrypted into DMCN mailboxes, and DMCN mail to the
	// bridge is delivered outbound over SMTP.
	bridgeEnabled    bool
	bridgeSMTPListen string
	bridgeAddress    string // bridge's DMCN address (default bridge@<domain>)
	bridgeDomain     string // the legacy email (SMTP) domain the bridge represents
}

func loadConfig() config {
	devMode := envBool("DMCND_DEV")
	c := config{
		httpListen:       envOr("DMCND_LISTEN", ":8443"),
		nodeListen:       envOr("DMCND_NODE_LISTEN", "/ip4/0.0.0.0/tcp/0"),
		domain:           envOr("DMCND_DOMAIN", "localhost"),
		dataDir:          envOr("DMCND_DATA_DIR", "data"),
		identityKeyPath:  os.Getenv("DMCND_IDENTITY"),
		tlsCert:          os.Getenv("DMCND_TLS_CERT"),
		tlsKey:           os.Getenv("DMCND_TLS_KEY"),
		devMode:          devMode,
		peers:            splitList(os.Getenv("DMCND_PEERS")),
		allowedPeers:     splitList(os.Getenv("DMCND_ALLOWED_PEERS")),
		seedPassphrase:   envOr("DMCND_SEED_PASSPHRASE", "dmcnd-dev-seed"),
		bridgeEnabled:    envBool("DMCND_BRIDGE_ENABLED"),
		bridgeSMTPListen: envOr("DMCND_BRIDGE_SMTP_LISTEN", ":2525"),
		bridgeAddress:    os.Getenv("DMCND_BRIDGE_ADDRESS"),
		bridgeDomain:     os.Getenv("DMCND_BRIDGE_DOMAIN"),
	}
	// Bridge address + SMTP domain default to the served domain.
	if c.bridgeAddress == "" {
		c.bridgeAddress = "bridge@" + envOr("DMCND_DOMAIN", "localhost")
	}
	if c.bridgeDomain == "" {
		c.bridgeDomain = envOr("DMCND_DOMAIN", "localhost")
	}
	// A self-hosted node has no peers to deny, so default the allow-set open in dev; production
	// deployments set DMCND_ALLOWED_PEERS explicitly (empty ⇒ deny-by-default).
	if len(c.allowedPeers) == 0 && devMode {
		c.allowedPeers = []string{"*"}
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
