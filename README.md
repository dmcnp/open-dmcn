# open-dmcn

The open core of the **DMCN Protocol (DMCNP)** — the protocol spoken by **DMCN**, the
Decentralized Mesh Communication Network: a peer-to-peer, end-to-end-encrypted
store-and-forward mail network where **cryptographic identity replaces SMTP-style
trust**. DMCN names the network; DMCNP names the protocol specified here.

This repository is the **canonical home of the core protocol schema** AND a complete,
single-binary **reference implementation** (`dmcnd`): everything an independent
implementation needs to interoperate — resolve addresses, verify identities, send and
receive mail — plus a runnable server that does it. It deliberately contains **no product
machinery**: operator fleet administration, hosting permits, provisioning, entitlements
and client-convenience surfaces are extensions maintained elsewhere (they ride their own
libp2p protocols and a generic, signature-covered extension surface — see SPEC.md §8).

## Reference daemon (`dmcnd`)

`cmd/dmcnd` is the reference implementation of the whole core protocol as **one process
for one domain** — where the product splits into a relay fleet, a separate stateless web
client, a provider funnel and a bridge, `dmcnd` folds the serving node, the webmail, the
SMTP bridge and the onion transport into a single self-hostable binary. It stays
**zero-knowledge**: the browser holds the keys and signs every operation; the server holds
no user private key, not even encrypted.

What it is:

- a **serving node** — durable mailbox + local record store + relay (`/dmcn/relay/1.0.0`,
  `/dmcn/peers`, `/dmcn/join`), authoritative for its own domain;
- a **webmail client** — the React SPA is embedded (`//go:embed`); all crypto is
  client-side (Web Crypto), the backend is an in-process proxy to the node;
- **self-service registration** — the browser generates keys and self-signs its record;
  the daemon attaches an operator routing credential and publishes it;
- an optional **SMTP bridge** (`DMCND_BRIDGE_ENABLED`) — inbound legacy email is
  signed+encrypted into DMCN mailboxes, DMCN→SMTP goes out over the bridge;
- **onion routing** — inherited transport, inert until the mesh has ≥3 relays.

### Build & run

The quickest way in — no clone, no Node, because the SPA is embedded in the binary:

```bash
go install dmcn.dev/open-dmcn/cmd/dmcnd@latest
go install dmcn.dev/open-dmcn/cmd/dmcndcli@latest   # operator CLI

# Dev: plain HTTP on localhost (a secure context for Web Crypto), DNS anchoring stubbed,
# and two throwaway accounts seeded so you can log in immediately.
DMCND_DEV=true DMCND_SEED_IDENTITIES=alice,bob dmcnd
# → open https://localhost:8443 (http in dev), import the seeded keys, send alice→bob.
```

From a clone:

```bash
make build                 # builds the embedded SPA (needs Node 20+) then bin/dmcnd
# or, since cmd/dmcnd/web/dist is committed:
go build -o bin/dmcnd ./cmd/dmcnd
```

`web/dist` is committed on purpose: it makes `go build ./...` work from a clean clone
without Node, and it is what lets `go install` produce a working daemon (the module zip
carries it, so `//go:embed web/dist` resolves for anyone installing from the proxy). Run
`make build-web` (or `make proto-web`) to regenerate it.

### Configuration (`DMCND_*` environment)

| Variable | Default | Purpose |
|---|---|---|
| `DMCND_DOMAIN` | `localhost` | the DMCN domain this daemon serves |
| `DMCND_LISTEN` | `:8443` | webmail HTTPS listen address |
| `DMCND_NODE_LISTEN` | `/ip4/0.0.0.0/tcp/0` | libp2p listen multiaddr |
| `DMCND_DATA_DIR` | `data` | mailbox/record store, sessions, seed keystore |
| `DMCND_IDENTITY` | — | persistent libp2p identity key (stable peer ID) |
| `DMCND_TLS_CERT` / `DMCND_TLS_KEY` | — | TLS cert/key; absent + not dev ⇒ autocert |
| `DMCND_DEV` | `false` | plain-HTTP-on-localhost + stub DAR DNS anchoring |
| `DMCND_PEERS` | — | bootstrap/discovery peer multiaddrs (federation) |
| `DMCND_ALLOWED_PEERS` | `*` in dev, else deny | libp2p federation allow-set (`*` = open) |
| `DMCND_STATIC_DNS` | — | static `_dmcn` pins for peer domains (DNS-free federation / seed-pin) |
| `DMCND_POLL_INTERVAL` | `10s` | webmail mailbox poll cadence |
| `DMCND_SEED_IDENTITIES` | — | **dev only**: comma-separated local-parts to mint + persist |
| `DMCND_SEED_PASSPHRASE` | `dmcnd-dev-seed` | encrypts the seed keystore |
| `DMCND_BRIDGE_ENABLED` | `false` | fold in the SMTP bridge |
| `DMCND_BRIDGE_SMTP_LISTEN` | `:2525` | bridge SMTP listen address |
| `DMCND_BRIDGE_ADDRESS` | `bridge@<domain>` | the bridge's own DMCN address |
| `DMCND_BRIDGE_DOMAIN` | `<domain>` | the legacy (SMTP) domain the bridge represents |
| `DMCND_BRIDGE_AUDIT_LOG` | — | append-only JSON audit log path |

### Federation

Two daemons on different domains interoperate the way email does — via DNS, not a global
DHT. Each publishes a `_dmcn.<domain>` TXT record (fingerprint + libp2p seed multiaddrs);
a sender resolves the recipient's domain, dials a seed, fetches the signed record, and
STOREs to the recipient's relay. In a dev/pinned cluster with no live DNS, list the peer
domains' anchors in a `DMCND_STATIC_DNS` file instead. Records are self-certifying, so a
wrong or hostile fleet is a denial-of-service risk, never a forgery vector.

### Operator CLI (`dmcndcli`)

The daemon configures itself (it seeds its domain at boot and provisions accounts through
the web UI), so `cmd/dmcndcli` is deliberately tiny — just the operator tasks that happen
*outside* the running process. It reads the daemon's on-disk state, so its output matches
what the daemon runs with.

```bash
# The _dmcn TXT record to publish so other domains can federate with yours:
dmcndcli dns --domain mesh.example --data-dir data \
  --seed /ip4/<public-ip>/tcp/7400/p2p/$(dmcndcli peer-id --identity data/node.key)
#   → _dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=<40-hex>; seed=/ip4/…/p2p/…"

# The libp2p peer ID for an identity key (created if missing) — for seed multiaddrs / allowlisting:
dmcndcli peer-id --identity data/node.key
```

## Layout

```
cmd/dmcnd/         the single-binary reference daemon (+ embedded web/ SPA)
internal/          the reference implementation (no API-stability promise):
  core/{crypto,identity,message,onion,domainverify,mailfilter}
  {node,relay,registry,keystore,peerpolicy,bridge,web,webcore,p2plog}
proto/
  identity.proto   dmcn.identity — identity records, credentials, domain authority,
                   blocklists, removals, fleet rosters, relay descriptors
  message.proto    dmcn.message  — the three-layer message model + encrypted envelope
  relay.proto      dmcn.relay    — the /dmcn/relay/1.0.0 wire protocol (mail interop)
  bridge.proto     dmcn.bridge   — OPTIONAL capability: SMTP-bridge attestation payloads
dmcnpb/            generated Go (committed; import dmcn.dev/open-dmcn/dmcnpb)
SPEC.md            the protocol reference (a snapshot of the reference implementation)
site/              dmcn.dev source: markdown content, templates, design system,
                   and the generator (a SEPARATE Go module — see below)
docs/              GENERATED dmcn.dev output, committed and published by Pages
```

`bridge.proto` is an **optional capability** like onion routing: a conforming
implementation need not run an SMTP bridge, but if it does, these are the attestation
formats (they are end-to-end-sealed message payloads, not wire ops).

## Schema rules

- **Never reuse a reserved field or arm number.** Vacated numbers carry `reserved` +
  gravestone comments; they are part of the protocol's history.
- **Breaking checks are PACKAGE-level** (`buf breaking`); the proto **package names**
  (`dmcn.identity`, …) are load-bearing for reflection-based consumers and never change.
- Extensions attach through the designed extension points (`IdentityRecord.
  operator_credentials`, `ext.`-prefixed `Credential.attributes` keys, separate libp2p
  protocol IDs) — never through new core fields.

## Build, test, regenerate

```bash
make build        # embedded SPA + bin/dmcnd
make test         # go test ./...
make proto        # regenerate dmcnpb/ from proto/ (requires buf + protoc-gen-go)
make proto-web    # regenerate the browser protobuf bundle (cmd/dmcnd/web/src/lib/proto)
make build-web    # rebuild the embedded SPA (needs Node 20+)
make site         # render dmcn.dev into docs/
make site-serve   # preview docs/ on localhost:8080 with production headers
```

## The documentation site (`dmcn.dev`)

[dmcn.dev](https://dmcn.dev) is the protocol's home — the specification, a quickstart and an
FAQ — and it is also the **vanity import path** for this module.

- `site/` holds the source and the generator. It is a **separate Go module**, so its markdown
  renderer never enters this module's dependency graph and `site/` is excluded from the zip
  that `go get` downloads. Run its tools with `GOWORK=off` (the Makefile does).
- `docs/` holds the **generated** output and is committed on purpose, the same way
  `cmd/dmcnd/web/dist` is: GitHub Pages publishes it straight from the branch, so the site
  depends on no CI and survives a repository transfer untouched. `make site-check` (wired
  into `make test`) fails if `docs/` is not exactly what `site/` generates, so stale output
  cannot reach the published site.
- The `/spec` page renders `SPEC.md` itself. There is no second copy to drift.
- `site serve` publishes the identical directory with the CSP and hardening headers GitHub
  Pages cannot send, so moving dmcn.dev behind our own TLS terminator is a DNS change rather
  than a rewrite.

## Status

A **reference snapshot, not a frozen specification**: the schema is versioned with the
reference implementation (`cmd/dmcnd`), which remains authoritative where they disagree.
The daemon is a proof-of-concept — in-memory/embedded stores, dev-oriented defaults — not
a hardened production deployment. `internal/` packages carry no API-stability promise;
the wire schema in `proto/` is the compatibility contract.

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). The license includes an express patent grant with defensive
termination: you may implement this protocol without fear of patent assertion by its
authors, and that grant terminates for anyone who initiates patent litigation over it.

## Trademarks

Two names, two meanings: **"DMCN"** identifies the *network* — the Decentralized Mesh
Communication Network of interoperating deployments — and **"DMCN Protocol" / "DMCNP"**
identifies the *protocol* specified in this repository. The Apache License covers the
code and schema here; it does **not** grant rights to either name or any associated
logos.

You are free to implement the protocol under any name of your own. Describing an
implementation or service as speaking the "DMCN Protocol" (or "DMCNP", or confusingly
similar) requires that it genuinely conform to the protocol specified here; describing
it as part of "DMCN" additionally means it actually interoperates with the network.
Names implying endorsement by or affiliation with the DMCN project require permission.
This keeps both names meaning what users think they mean: DMCNP is the protocol, and
DMCN is the network of things that truly speak it.
