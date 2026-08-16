---
title: Try it
description: Run dmcnd, the reference DMCNP server, to watch the protocol work end to end — then read the spec and build your own.
---

# Try it

`dmcnd` is a small reference server: one domain, one process, webmail included. It exists so
you can watch the protocol work before you read 200 lines of spec, and so you have something
concrete to check your own implementation against.

It is **not** the protocol. It's one implementation of it, and a deliberately simple one —
embedded stores, dev-friendly defaults, no operational hardening. Don't put it in front of
real users. Do read it alongside [the spec](/spec) when the prose is ambiguous.

## Run it

You need **Go 1.25+**. The web UI is committed pre-built, so you don't need Node.

```bash
git clone {{repo}}
cd open-dmcn
go build -o bin/dmcnd ./cmd/dmcnd

DMCND_DEV=true DMCND_SEED_IDENTITIES=alice,bob ./bin/dmcnd
```

Open `http://localhost:8443`, import one of the seeded keys, and send alice → bob. Dev mode
serves plain HTTP on localhost — still a secure context, so Web Crypto works — and stubs the
DNS anchoring so you don't need real records to poke at it.

## What to watch

The interesting part isn't the UI, it's what the server never sees.

Keys are generated in the browser and stay there. Every operation is signed client-side. The
server holds no private key for any account — not even an encrypted one — so a fetch is
authorised by answering a 32-byte challenge with a signature, not by presenting a password
the server could store.

Put a proxy in front of it and watch the traffic: sealed envelopes, padded to fixed size
classes, and a header you can list without touching a body.

## Point a real domain at it

Other domains find yours through DNS. The CLI prints the exact record:

```bash
dmcndcli dns --domain mesh.example --data-dir data \
  --seed /ip4/<public-ip>/tcp/7400/p2p/$(dmcndcli peer-id --identity data/node.key)
```

```
_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=<40-hex>; seed=/ip4/…/p2p/…"
```

`fp=` is your domain's trust anchor — the first 20 bytes of `SHA-256(ed25519_pub ‖
x25519_pub)` of its root key. Anyone resolving an address on your domain checks what your
server hands them against that fingerprint, so they never have to trust the server itself.

Two daemons on two domains then interoperate the way email already does: resolve the
recipient's domain, dial a seed, fetch the signed record, store the sealed envelope. For a
local cluster with no real DNS, list the peer anchors in a `DMCND_STATIC_DNS` file instead —
the resolver checks it before DNS, so you can exercise the whole path offline.

## Configuration

Everything is environment-driven. These are the ones you'll actually touch:

| Variable | Default | Purpose |
|---|---|---|
| `DMCND_DOMAIN` | `localhost` | the domain this daemon serves |
| `DMCND_LISTEN` | `:8443` | webmail listen address |
| `DMCND_DATA_DIR` | `data` | mailboxes, records, keys |
| `DMCND_DEV` | `false` | plain HTTP on localhost, stubbed DNS anchoring |
| `DMCND_PEERS` | — | peers to bootstrap from |
| `DMCND_SEED_IDENTITIES` | — | **dev only**: accounts to mint at boot |
| `DMCND_BRIDGE_ENABLED` | `false` | turn on the SMTP bridge |

The full list — TLS, libp2p listen addresses, federation allow-sets, bridge options — is in
the [repository README]({{repo}}#configuration-dmcnd_-environment).

Note the federation default: **deny**. Outside dev mode a node admits no peers until you
either allowlist them or hand them a valid credential.

## The SMTP bridge

```bash
DMCND_BRIDGE_ENABLED=true ./bin/dmcnd
```

Inbound legacy mail gets checked with SPF/DKIM/DMARC at the bridge, and the verdict travels
as a signed attachment *inside* the sealed envelope. So the recipient's client verifies the
bridge's attestation against the bridge's own published identity, rather than trusting
whichever relay carried it.

**The honest bit:** mail crossing a bridge is TLS-in-transit on the legacy side, not
end-to-end encrypted. A bridge is there for interoperability, not security. Mail that stays
inside DMCN never leaves the sender's device unsealed.
