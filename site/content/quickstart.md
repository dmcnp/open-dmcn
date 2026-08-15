---
title: Quickstart
description: Build and run dmcnd, the single-binary DMCNP reference daemon — a serving node, webmail, an optional SMTP bridge and onion transport in one process for one domain.
---

# Quickstart

`dmcnd` is the reference implementation of the whole core protocol as **one process for one
domain**. Where a production deployment splits into a relay fleet, a stateless web client
and a bridge, `dmcnd` folds the serving node, the webmail, the SMTP bridge and the onion
transport into a single self-hostable binary.

It stays zero-knowledge throughout: the browser holds the keys and signs every operation,
and the server holds no user private key — not even an encrypted one.

## Build it

You need **Go 1.25+**. Node is only required if you want to rebuild the embedded web UI;
`cmd/dmcnd/web/dist` is committed precisely so a fresh clone builds without it.

```bash
git clone https://github.com/mertenvg/open-dmcn
cd open-dmcn

make build                          # embedded SPA + bin/dmcnd (needs Node 20+)
go build -o bin/dmcnd ./cmd/dmcnd   # or just this, using the committed dist/
```

## Run it locally

Dev mode serves plain HTTP on localhost — which is still a secure context, so Web Crypto
works — stubs the DNS anchoring, and mints throwaway accounts so you can send a message to
yourself within a minute of cloning.

```bash
DMCND_DEV=true DMCND_SEED_IDENTITIES=alice,bob ./bin/dmcnd
```

Open `http://localhost:8443`, import one of the seeded keys, and send `alice → bob`. The
seed keystore is encrypted with `DMCND_SEED_PASSPHRASE` (default `dmcnd-dev-seed`).

## Configuration

Everything is environment-driven. The defaults are chosen for a single-domain deployment.

| Variable | Default | Purpose |
|---|---|---|
| `DMCND_DOMAIN` | `localhost` | the DMCN domain this daemon serves |
| `DMCND_LISTEN` | `:8443` | webmail HTTPS listen address |
| `DMCND_NODE_LISTEN` | `/ip4/0.0.0.0/tcp/0` | libp2p listen multiaddr |
| `DMCND_DATA_DIR` | `data` | mailbox/record store, sessions, seed keystore |
| `DMCND_IDENTITY` | — | persistent libp2p identity key (stable peer ID) |
| `DMCND_TLS_CERT` / `DMCND_TLS_KEY` | — | TLS cert/key; absent and not dev ⇒ autocert |
| `DMCND_DEV` | `false` | plain HTTP on localhost + stub DAR DNS anchoring |
| `DMCND_PEERS` | — | bootstrap/discovery peer multiaddrs (federation) |
| `DMCND_ALLOWED_PEERS` | `*` in dev, else deny | libp2p federation allow-set (`*` = open) |
| `DMCND_STATIC_DNS` | — | static `_dmcn` pins for peer domains (DNS-free federation) |
| `DMCND_POLL_INTERVAL` | `10s` | webmail mailbox poll cadence |
| `DMCND_SEED_IDENTITIES` | — | **dev only**: comma-separated local-parts to mint |
| `DMCND_SEED_PASSPHRASE` | `dmcnd-dev-seed` | encrypts the seed keystore |
| `DMCND_BRIDGE_ENABLED` | `false` | fold in the SMTP bridge |
| `DMCND_BRIDGE_SMTP_LISTEN` | `:2525` | bridge SMTP listen address |
| `DMCND_BRIDGE_ADDRESS` | `bridge@<domain>` | the bridge's own DMCN address |
| `DMCND_BRIDGE_DOMAIN` | `<domain>` | the legacy SMTP domain the bridge represents |
| `DMCND_BRIDGE_AUDIT_LOG` | — | append-only JSON audit log path |

Note the federation default: **deny**. A node that is not in dev mode admits no peers until
you say so, either by allowlisting peer IDs or by presenting a valid credential.

## Put your domain on the network

Other domains find yours through DNS. The operator CLI prints the exact record to publish,
including the fingerprint of your domain's root key and a seed multiaddr built from your
node's peer ID:

```bash
dmcndcli dns --domain mesh.example --data-dir data \
  --seed /ip4/<public-ip>/tcp/7400/p2p/$(dmcndcli peer-id --identity data/node.key)
```

```
_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=<40-hex>; seed=/ip4/…/p2p/…"
```

`fp=` is the trust anchor — the first 20 bytes of `SHA-256(ed25519_pub ‖ x25519_pub)` of
your domain's root key. Anyone resolving an address on your domain verifies what your fleet
serves against that fingerprint, so the fleet never has to be trusted.

## Federate with another domain

Two daemons on different domains interoperate the way email does. Each publishes its
`_dmcn` record; a sender resolves the recipient's domain, dials a seed, fetches the signed
record and stores the sealed envelope to the recipient's relay.

For a local cluster with no live DNS, list the peer domains' anchors in a
`DMCND_STATIC_DNS` file instead — the resolver consults it before real DNS, so you can
exercise the whole path offline.

## Turn on the SMTP bridge

```bash
DMCND_BRIDGE_ENABLED=true DMCND_BRIDGE_SMTP_LISTEN=:2525 ./bin/dmcnd
```

Inbound legacy mail is authenticated with SPF/DKIM/DMARC at the bridge, and the verdict
travels as a signed `BridgeClassificationRecord` attachment *inside* the sealed envelope —
so the recipient's client verifies the bridge's attestation against the bridge's published
identity rather than trusting the relay that carried it.

**The honest caveat:** mail crossing a bridge is TLS-in-transit on the legacy side, not
end-to-end encrypted. A bridge is an interoperability affordance, not a security boundary.
Mail that stays inside DMCN never leaves the sender's device unsealed.

## What this is not

`dmcnd` is a proof of concept: embedded stores, dev-oriented defaults, no operational
hardening. Onion routing is inherited from the protocol and stays inert until a mesh has at
least three relays. Treat it as the executable half of the specification — the thing you
read alongside `SPEC.md` when the prose is ambiguous — rather than as something to put in
front of real users today.
