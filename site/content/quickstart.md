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

You need **Go 1.25+**. That's it — the web UI ships pre-built inside the binary, so there's
no Node step.

```bash
go install {{module}}/cmd/dmcnd@latest

DMCND_DEV=true dmcnd
```

Open `http://localhost:8443` and register an account. Dev mode serves plain HTTP on localhost
— still a secure context, so Web Crypto works — and stubs the DNS anchoring, so you don't
need real records to poke at it.

To watch mail move between two accounts, register a second one in a private window: keys live
in browser storage, so a separate profile is a separate account. Or just send to yourself —
the round trip is the same.

If `dmcnd` isn't found, `go install` put it in `$(go env GOPATH)/bin`, which isn't on your
`PATH` yet.

Want to read the code alongside [the spec](/spec)? Clone it instead:

```bash
git clone {{repo}} && cd open-dmcn
go build -o bin/dmcnd ./cmd/dmcnd
```

## What to watch

The interesting part isn't the UI, it's what the server never sees.

Your keys are generated in the browser and stay there. The browser self-signs its identity
record, and only the signed *public* record reaches the server. Every operation is signed
client-side, so a fetch is authorised by answering a 32-byte challenge with a signature — not
by presenting a password the server could store.

The daemon holds no account private key. Not an encrypted one, not a recoverable one, none.
The only keys it mints are the domain's own — the root key behind its authority record, and
the SMTP bridge's identity if you turn the bridge on. Neither can read anyone's mail.

Put a proxy in front of it and watch the traffic: sealed envelopes, padded to fixed size
classes, and a header you can list without touching a body.

## Point a real domain at it

Other domains find yours through DNS. The operator CLI prints the exact record:

```bash
go install {{module}}/cmd/dmcndcli@latest

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
| `DMCND_BRIDGE_ENABLED` | `false` | turn on the SMTP bridge |
| `DMCND_BRIDGE_DELIVERY_MODE` | `stub` | `smtp` to actually send outbound mail (default captures it in memory) |

The full list — TLS, libp2p listen addresses, federation allow-sets, bridge options — is in
the [repository README]({{repo}}#configuration-dmcnd_-environment).

Note the federation default: **deny**. Outside dev mode a node admits no peers until you
either allowlist them or hand them a valid credential.

## The SMTP bridge

```bash
DMCND_BRIDGE_ENABLED=true dmcnd
```

Inbound legacy mail gets checked with real SPF/DKIM/DMARC at the bridge, and the verdict travels
as a signed attachment *inside* the sealed envelope. So the recipient's client verifies the
bridge's attestation against the bridge's own published identity, rather than trusting
whichever relay carried it.

Outbound is opt-in and off by default:

```bash
DMCND_BRIDGE_ENABLED=true DMCND_BRIDGE_DELIVERY_MODE=smtp DMCND_BRIDGE_DKIM_KEY=dkim.pem dmcnd
```

Without `DMCND_BRIDGE_DELIVERY_MODE=smtp` the bridge accepts and translates outbound mail but
captures it in memory instead of sending it, so installing the daemon never starts emitting live
mail at anyone. Turn it on and you want a DKIM key too — unsigned mail from a new host is filtered
almost everywhere.

**The honest bits.** Mail crossing a bridge is TLS-in-transit on the legacy side, not end-to-end
encrypted; a bridge is there for interoperability, not security, and mail that stays inside DMCN
never leaves the sender's device unsealed. And SPF, DKIM and DMARC are only meaningful if the DNS
they read is real — `DMCND_BRIDGE_AUTH_MODE=stub` exists for offline development and turns the
verdict into a rubber stamp, so never run it anywhere real mail arrives.
