# Porting notes — open-dmcn core ← dmcn (product)

open-dmcn's `internal/` core is a **copy** of the DMCN product's core Go, stripped of
product/operator surfaces and retargeted onto `dmcn.dev/open-dmcn`. The two
codebases evolve independently; **wire compatibility is guaranteed by the shared proto**
(`open-dmcn/proto` ↔ the product's `proto/core`, both generating `dmcnpb`), not by shared
Go code.

## Rules

- **Never hand-edit `dmcnpb/` or `proto/`** — regenerate (`buf generate`). The schema is the
  compatibility contract.
- Keep the local deltas below **minimal and mechanical** so an upstream core bugfix re-ports
  as a near-clean cherry-pick.
- When pulling an upstream fix into a copied package, re-apply the listed deltas.

## Provenance

- **Ported from:** `github.com/mertenvg/dmcn` @ `ca1be4793e8c2b9eb73f2bdb354c189052866981`
- **Mechanical retarget (whole tree):** `github.com/mertenvg/dmcn/internal/...` →
  `dmcn.dev/open-dmcn/internal/...`; every `.../internal/proto/dmcnextpb` import
  **removed** (those symbols do not exist here); `open-dmcn/dmcnpb` unchanged.

## Copied as-is (retarget only)

`internal/core/{crypto,domainverify,message,mailfilter,onion}`, `internal/{keystore,registry,peerpolicy,p2plog,webcore}`.

## Copied with deltas

| Package | Files dropped | Core edits |
|---|---|---|
| `core/identity` | `permit.go`, `rate.go`, `subauthorityrequest.go` (+ their tests) | `identity.go`: removed `HasRateCredential`/`SendRateCredential`/`IssueSendRateCredential` (referenced the dropped `rate.go`). `OperatorCredentials` field + its proto mapping kept (generic core slot). |
| `core/pairing` | (the `Clone*`/`Marshal*`/`Build*`/`Extract*` device-pairing funcs) | `pairing.go` reduced to the ephemeral-address helpers (`IsEphemeralAddress`, `EphemeralAddress`, `NewEphemeralRecord`, consts) so `node/resolver.go` + `relay/putrecord.go` compile; those branches are inert (a reference node never mints pairing addresses). |
| `relay` | `operate.go`, `mailboxext.go` (+ their tests + the op e2e tests: sendcounter/quota/access/personalkv/stat/drain/fleet/mailbox_quota/sentcopy) | `relay.go`: `Start()`/`Stop()` no longer register `/dmcn/operate` + `/dmcn/mailbox-ext`; the fleet-permit surface stripped (fields, `WithOperatorPubKey/WithPermits/WithPermitPersist`, `fleetManaged/IsPermittedDomain/PermittedDomains/AcceptPermit`, the `fleetGuard` blocks in `acceptEnvelope`). `putrecord.go`: dropped the fleet routing-grant gate on identity pushes. The dmcnpb-clean but now-inert `quota/access/personalkv/accounts/mailfilter` stores are **retained** as legitimate relay substrate (see P6). |
| `node` | `permit.go` | `provision.go` trimmed to the credential-bundle accessors + persistence, re-serialized onto `dmcnpb.CredentialBundle` (was `dmcnextpb.ProvisionPush`); the `/dmcn/provision` service dropped. `node.go`: removed `Config.OperatorPubKey/PermitsDir/ProvisionDomain`, the permit-load / fleet-relayOpts / `startPermitService` / inert-boot / `startProvisionService` blocks — the node boots bare (Mailbox + RecordStore + join, authoritative for its own domain). `relaykey.go`: dropped the `PermittedDomains()` announce loop. `placement.go` replaced with a single-node stub (`ComputeRelayHints`/`ReserveRelayHints` return the node's own hint; HRW ranking + STAT-probe + RequestMailbox reserve removed). |
| `core/placement` | (entire package) | Unused after the `node/placement.go` stub. |
| `relay` (P1 add) | — | `relay.go`: **added** `StoreLocal(ctx, senderAddr, sig, env)` — an exported in-process STORE that wraps `acceptEnvelope`+`storeRespError`, so the folded daemon's webmail backend can STORE without a libp2p self-dial. Pure addition; no upstream symbol changed. |
| `web` (from product `cmd/dmcn-web/internal/{api,server}`) | `pair.go` (+ its test), the send-cap tests + the mailbox-ext/KV tests | `api/messages.go`: dropped the `ConsumeSend`/`SendCaps`/`messageTracker` send-cap surface (a self-hoster is its own send authority) — `RelayRouter` is now Connect/Store/Onion only. `api/mailbox.go`: **redesigned transport-neutral** — `RelayProxy` is `Challenge`/`List`/`Body`/`Delete` over `(address, nonce, signature)` instead of a held-open `network.Stream`, dropping the `dmcnextpb` KV ops; the two-phase challenge/complete (zero-knowledge: browser signs each nonce) is preserved. `server/server.go`: `RegisterAPI` drops the `PairHandler` param + the two `/api/v1/pair/*` routes; account/Stripe wiring kept inert (pruned in P2). |

## Single-binary daemon (`cmd/dmcnd`, new — not a port)

The reference daemon folds a serving node + webmail into one process. New code, no product counterpart:
- `main.go` — `node.New(Mailbox)` (serving, not `ClientOnly`) + HTTP server; wires the web handlers to the local node via the in-process adapters; env-driven (`DMCND_*`).
- `relayadapter.go` — `inProcRelay` (`api.RelayProxy`) verifies each op's nonce signature against the address's resolved record, then calls `Relay().Mailbox().List/GetBody/Delete` directly; `inProcRouter` (`api.RelayRouter`) STOREs via `Relay().StoreLocal` when the hint is this node, else dials (`ClientStorePreSigned`) — so a self-hosted domain and federation both work.
- `seed.go` — boot-time domain seed (root key → signed DAR → static `_dmcn` anchor) + optional dev identities (self-signed record + root-signed routing credential), keys held in an encrypted seed keystore. The daemon never uses those private keys to serve (zero-knowledge); they exist for browser import + the e2e test.
- `dmcnd_test.go` — in-process integration test (seed → send alice→bob → challenge/list/body/delete → wrong-key rejected), the P1 gate.
- `web/` — the SPA (copied + pruned in P2, below).

## Webmail frontend (`cmd/dmcnd/web`, P2 — from product `cmd/dmcn-web/web`)

Copied from the product SPA and pruned to core-only. Build with `make build-web` (`vite build`);
`//go:embed web/dist` embeds the result. Key deltas:
- **Proto bundle** `src/lib/proto/dmcn.js` **regenerated core-only** (`make proto-web`) — identity +
  message + relay, dropping the product's `pairing.proto` + `countersign.proto`. `bridge.js` kept (P4).
- **Per-account state → IndexedDB.** The single seam `lib/api/personalStore.ts` (`PersonalStore`, under
  Sent/flags/labels/contacts/settings) and `lib/api/filterRest.ts` (`MailFilterClient`) were
  **reimplemented against IndexedDB** (new `personal` object store in `crypto/idb.ts`, namespaced by
  owner address). The product synced these to the relay via the mailbox-ext personal-KV ops, which the
  open protocol does not carry — so the higher stores/hooks/components are untouched but now local-only
  (single-device). The block/allow list becomes an advisory client-side hide (no relay-side drop).
- **Dropped pages** (product surfaces): `Admin`, `PairDevice`, `DeviceRequests`; their routes/nav removed
  from `App.tsx`/`AppLayout.tsx`. `Register.tsx` reduced to a placeholder (self-service signup is the
  provider funnel; real local registration is P3).
- **Dropped crypto**: `pairing.ts`, `countersign.ts`, `cliKeystore.ts`; the `dmcn.pairing.*` /
  `dmcn.countersign.*` encoders in `protobuf.ts`. `keyPairToPayloadJSON` (a keystore-format helper, not
  pairing-specific) moved to `crypto/keys.ts`. `exportFile.ts`/`bridgeAttest.ts` kept.
- **Dropped Stripe + account service**: `@stripe/*` deps + the Settings billing UI + the `client.ts`
  account-service block (register/billing/countersign/pair/account-auth) + `SessionRenewer`'s account
  auth. `server.go` CSP no longer sets `Stripe: true` (strict same-origin `script-src 'self' 'nonce-…'`).

## Self-service registration (P3)

The daemon is the operator for its one domain, so registration is a fraction of the product's b2c
funnel — no policy/DNS-proof/permit/reserved/billing/user-directory. Zero-knowledge holds: the
browser generates keys + self-signs the record; only the signed public record reaches the server.
- **Backend** `internal/web/api/register.go` (`RegisterHandler`) decodes the request, verifies the
  self-signature (`rec.Verify()`) + address match, then calls the daemon's `ProvisionFunc`. Route
  `POST /api/v1/register` wired in `server.go` (public, rate-limited).
- **`cmd/dmcnd/register.go`** (`provisionIdentity`) is the operator half: domain check + duplicate
  check, then `rec.IssueRoutingCredential(root, hints)` + `PublishIdentity` — the same operator step
  as the boot seed, for a browser-provided record. `main.go` wires it as the provision closure.
- **Frontend** `Register.tsx` restored to a real single-domain signup (browser keygen → self-sign →
  `register()` → local keystore → `loginWithKeys`); `client.ts` `register()` re-added, pointing at the
  LOCAL endpoint (no account service). Dropped the product's domain-picker / countersign-pending /
  admin-custody / registration-closed branches.
- **Deferred:** a browser admin **domain-init** UI (`PublishDAR`) — the boot seed already publishes the
  domain's DAR, so single-domain needs no runtime init; a multi-domain admin console is future work.
- Tests: `internal/web/api/register_test.go` (handler decode/verify/error-mapping) +
  `cmd/dmcnd/register_test.go` (provision → resolve + duplicate/off-domain guards).

## SMTP bridge, folded onto the shared node (P4 — from product `internal/bridge`)

Copied + retargeted; the bridge now SHARES the daemon's node instead of running its own. Deltas:
- **`bridge.go`**: `New(ctx, cfg)` (which created its own `node.New` + registered its identity) →
  `New(ctx, n *node.Node, bridgeKP *identity.IdentityKeyPair, cfg)`. Dropped the node creation, the
  identity registration + key load/gen (`loadOrGenerateBridgeKeys`) — the DAEMON provisions the bridge
  identity (`seedBridgeIdentity`: BridgeCapability + routing credential) and owns the node lifecycle
  (`Stop()` no longer closes it). `Config` trimmed to SMTP↔DMCN translation only (dropped the
  libp2p/relay/credential/permit/StaticDNS knobs that live on `node.Config`). Removed the
  `bridgeSendCounter` (the `ClientConsumeSendInject` touchpoint).
- **`outbound.go`**: dropped the `SendRateCounter` interface + the entitlement-aware daily
  bridged-recipients cap (both rode the removed `relay.SendCountResult`); the flat per-sender hourly
  limiter stays. A self-host is its own send authority.
- **Deps added** to `go.mod` (offline from cache): `go-smtp`, `go-msgauth`, `go-message`, `go-sasl`,
  `go-proxyproto`, `blitiri…/spf` — now listed as direct requires (the bridge imports them); only
  `go-sasl` (transitive via `go-smtp`) stays `// indirect`.
- **Tests**: dropped `integration_test.go` (2 multi-node tests that assumed the bridge owns its node);
  its end-to-end coverage is replaced by `cmd/dmcnd/bridge_test.go` (`TestBridgeFold`: inbound legacy
  email → recipient's DMCN mailbox on the shared node). All bridge unit tests (classify/mime/inbound/
  outbound/dkim/attest/smtp) pass unchanged. Wired into `cmd/dmcnd/main.go` behind `DMCND_BRIDGE_*`.
- Frontend `bridgeAttest.ts` was kept in P2, so the webmail already shows the bridge trust tier.

## Federation + onion (P5)

The single-domain daemon already had the resolver + relay + onion from the copied core; P5 wired the
federation config and proved cross-domain mail works on the folded daemon.
- **`node.MergeStaticDNS`** (small delta in `node.go`): merges static `_dmcn` entries instead of
  replacing, so a serving node's own-domain anchor coexists with operator-configured peer domains.
  `cmd/dmcnd/seed.go` now merges its own-domain anchor; `main.go` loads **`DMCND_STATIC_DNS`** (a static
  `_dmcn` file for peer domains — DNS-free federation / operator seed-pin) into the node config first.
- **`cmd/dmcnd/federation_test.go`** (`TestFederation`): two serving nodes on distinct domains
  (`a.test`, `b.test`); `alice@a.test` (node A) resolves `bob@b.test` from B's fleet (cross-domain,
  DNS-seeded), STOREs across the federation to B, and bob reads + decrypts it on B — the daemon's real
  send/read paths (the in-process router/proxy the webmail uses). Proves the protocol's core purpose.
- **Onion** is inherited + wired (`relayadapter.SendOnionPreSigned` → `node.SendOnionPreSigned`,
  relaxed) and inert on a single node (needs ≥3 relay descriptors, discovered via the fleet
  relay-descriptor op — serving nodes advertise their own via `seedOwnRecords`). Coverage is the copied
  core: `internal/core/onion/*`, `internal/relay/onion_test.go`, and the multi-node
  `internal/node/onion_integration_test.go` — all pass. No daemon-level onion delta was needed.

## Cleanup + docs (P6)

- **Docs**: `README.md` rewritten to document the reference daemon (`dmcnd`) — what it is, build/run,
  the full `DMCND_*` config table, and federation. `SPEC.md` needs no change (it specifies the wire
  protocol, which the daemon doesn't alter).
- **Store prune — a measured one.** `sendcounter.go` (+ its store field/option/node wiring) was
  **removed**: after dropping `operate.go`'s `ConsumeSendInject` (P0) and the bridge send-cap (P4),
  nothing reads or writes it — it was truly dead. The other operator stores
  (`quota/access/mailfilter/personalkv`) are **kept**: they are the relay's enforcement + storage
  substrate (per-account quota, access lock, block/allow filter, owner KV), default to safe behavior
  when unpopulated (unlimited / open / permit-all / empty), and removing their gates from the copied
  `acceptEnvelope`/`handleFetch` would be a large `relay.go` delta that fights the clean-re-port goal.
  Only their extension-plane INSTALL ops (which rode `operate.go`/`mailboxext.go`) are gone. `accounts`
  is retained and live (populated at authenticated FETCH).
- **`go.mod` is a complete, standalone module** (`go mod tidy` run with `GOWORK=off`). open-dmcn does
  NOT depend on the product — it builds, vets, and passes its full test suite on its own
  (`GOWORK=off go build/test ./...`). The `go.work` in the parent tree only lets the *product* consume
  this local checkout of `dmcnpb` before publish; it is not a dependency of open-dmcn. `go-libp2p` is
  pinned to **v0.47.0** to match upstream (at v0.48 it re-absorbed the `core/*` packages that also live
  in the legacy standalone `go-libp2p/core` module, which collides with open-dmcn's direct `core/*`
  imports — tidy without the pin picks v0.48 and fails on that overlap).

## Operator CLI (P7)

`cmd/dmcndcli` — a deliberately tiny standalone tool for the operator tasks that happen OUTSIDE the
running daemon (the daemon seeds its domain at boot and provisions accounts via the web UI). Reads
the daemon's on-disk state so its output matches what the daemon runs with:
- **`peer-id --identity <path>`** — load-or-create the libp2p identity key + print the peer ID (for
  seed multiaddrs / allowlisting). Mirrors the product's `dmcn-node peer-id`.
- **`dns --domain <d> [--data-dir <dir>] [--seed <m>]…`** — load the domain root key from the daemon's
  seed keystore (alias `__domain_root__@<domain>`, path `<data-dir>/seed-keystore.json` — MUST match
  `cmd/dmcnd/seed.go`) and print the `_dmcn.<domain>` TXT record to publish for federation. The daemon
  also logs this record at boot (`seed.go`).
- Tests: `cmd/dmcndcli/main_test.go` pins the TXT format + that the CLI's fingerprint equals the
  daemon's DAR anchor for the same keystore (a live E2E confirmed the match across a real boot).

## Status — Stage C complete

All seven phases (P0–P7) are ported. `open-dmcn` is a complete, independent, single-binary reference
implementation of the DMCN core protocol: serving node + webmail + self-service registration + SMTP
bridge + onion + federation, with a small operator CLI. Its `go.mod` is complete and standalone —
`GOWORK=off go build/test ./...` is green with no dependency on the product. Ready to stand as its own
repository (any remaining polish is SPEC/README only).

## Gate at each port

`go build ./...`, `go vet ./...`, `go test ./...` all green in `open-dmcn` (verified at the P0 port above: the full copied-core suite passes).
