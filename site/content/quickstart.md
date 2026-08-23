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

Open `http://localhost:8080` and register an account — the daemon prints that exact URL on
startup, so you can copy it rather than typing a scheme. Dev mode serves plain **HTTP** on
`:8080`; production serves HTTPS on `:443`, and the ports differ deliberately so a browser is
never guessing which scheme applies.

Plain HTTP is fine here: localhost is a secure context, so Web Crypto works. Dev mode also
stubs the DNS anchoring, so you don't need real records to poke at it.

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

In dev mode it does mint the domain's own root key, locally, so that one command gets you a
working domain. On a real domain it does not: the root is created on your machine and the node
only ever receives the signed record it produced. See below — that difference is the reason the
setup has two halves.

Put a proxy in front of it and watch the traffic: sealed envelopes, padded to fixed size
classes, and a header you can list without touching a body.

## Point a real domain at it

Two machines, and the split between them is the point.

The **node** holds its own libp2p key and a signed copy of your domain's authority record. The
**machine you run `dmcndcli` on** holds the domain root key, and never gives it up. Only three
things ever cross the gap: a peer ID, a signed authority record, and signatures. No private key
moves.

That matters because the root key is what every other domain checks your records against. A node
that holds it is a node whose compromise mints addresses on your domain; a node that doesn't,
isn't. `dmcnd` used to mint the root on the node — one command, and your trust anchor lived on an
internet-facing box. It no longer will: a live daemon has no way to create an authority record, so
it waits until you hand it one and serves nothing until then.

("Offline" here means *not the node*. The machine running `dmcndcli` still has to reach the daemon
over HTTPS. A genuinely air-gapped root would need the signing step carried across by hand, which
the format allows and the CLI does not yet do.)

**1. [node]** Install the daemon and get its peer ID. Set the libp2p port first — it goes into DNS
and is awkward to change later.

```bash
go install {{module}}/cmd/dmcnd@latest

export DMCND_DOMAIN=mesh.example
export DMCND_NODE_LISTEN=/ip4/0.0.0.0/tcp/7400
dmcnd peer-id
```

**2. [admin]** On a different machine — ideally one that stays offline — install the CLI.

```bash
go install {{module}}/cmd/dmcndcli@latest
```

**3. [admin]** Mint the root and sign the domain's authority record. This touches no network.

```bash
dmcndcli domain init --domain mesh.example \
  --seed /ip4/<public-ip>/tcp/7400/p2p/<peer-id from step 1> \
  --keystore root.enc --passphrase '<high-entropy>'
```

It prints the DNS record. The authority record it signs sets two things that are easy to miss and
load-bearing: countersigning is required (so an address is unusable until the root has attested it)
and the reserved local-parts are seeded (so `postmaster@` and `countersign@` are not first-come).

**4. [admin]** Publish the TXT record it printed.

```
_dmcn.mesh.example.  TXT  "dmcn-verification=v1; fp=<40-hex>; seed=/ip4/…/p2p/…"
```

`fp=` is your domain's trust anchor — the first 20 bytes of `SHA-256(ed25519_pub ‖ x25519_pub)` of
its root key. Anyone resolving an address on your domain checks what your server hands them
against that fingerprint, so they never have to trust the server itself.

**5. [admin]** Back up `root.enc` offline, and keep the passphrase somewhere else.

Lose it and no address on the domain can ever be issued or rotated again. There is no recovery
path except publishing a new `fp=` and having every correspondent re-verify you, and nobody can
re-issue it for you.

**6. [node]** Start the daemon.

```bash
dmcnd
```

It will report that it has no authority record and wait, serving nothing — no webmail, no
petitions. That is the point: with no authority record the reader-side address check has nothing to
enforce and would fail open, so the daemon declines to be a domain rather than be a permissive one.

**7. [admin]** Hand it the record.

```bash
dmcndcli domain publish --domain mesh.example \
  --peers /ip4/<host>/tcp/7400/p2p/<peer-id> --keystore root.enc
```

This is the same record push `remove-address` uses, and it sends only the signed public record —
the root key stays where it is. The daemon picks it up within a few seconds and starts serving. It
is stored persistently, so this is a one-time step: restarts skip it.

**8. [you]** Get yourself a mailbox — through the same flow as everyone else, below. You are the
admin, so you assign your own.

### Give someone a mailbox

There is no sign-up form on a live domain, because there is no key here that could create an
address. Instead:

- **[them]** They open your domain in a browser and ask for a mailbox. Their keys are generated
  and stay in that browser; only the public half is sent. They get a 12-digit code.
- **[out of band]** They read you the code, however they normally reach you. **That contact is the
  authorization** — there is no allowlist to maintain and no queue to triage, because a petition is
  worth nothing until you act on a code somebody gave you.
- **[admin]** You assign an address:

  ```bash
  dmcndcli petition assign --code 0428-9173-5560 --address them@mesh.example \
    --url https://mesh.example --keystore root.enc --passphrase '<…>'
  ```

- **[them]** Their browser picks the address up on its own and the mailbox opens. You never have
  to recite it, and you never handle their keys.

Two properties make this safe rather than merely convenient. **The petitioner cannot choose their
address** — you do — so there is nothing in a petition worth taking, and one you ignore simply
expires (24h by default, `DMCND_PETITION_TTL`). And **the code alone is not enough**: completing a
petition requires the private key the browser proved it held, so an overheard code gets an
eavesdropper nothing.

To free an address later — a lost key, someone leaving — `dmcndcli remove-address` publishes a
root-signed tombstone, after which the address can be petitioned for again.

### Ports

| Port | Direction | What for | When |
|---|---|---|---|
| `7400` (`DMCND_NODE_LISTEN`) | inbound | libp2p federation — **this is the port in your published `seed=`** | any live domain |
| `443` (`DMCND_LISTEN`) | inbound | webmail, and the ACME challenge for its certificate | always |
| `25` | inbound | SMTP — your domain's MX | bridge enabled |
| `25` | **outbound** | delivering to other providers' mail servers | `DMCND_BRIDGE_DELIVERY_MODE=smtp` |
| `53` | outbound | DNS: other domains' `_dmcn` anchors, and MX lookups | always |
| ephemeral | outbound | dialling other domains' seeds | always |

Three of these catch people out:

- **Many hosting providers block outbound port 25 by default** and want a support ticket before
  they'll open it. A bridge that receives fine but never delivers is usually this, not a DMCN bug.
- **Inbound 25 needs privileges** (`setcap CAP_NET_BIND_SERVICE`, or systemd `AmbientCapabilities`),
  as does 443. The bridge's own default is `:2525`, which is convenient for testing and which no
  sending mail server will ever try — set `DMCND_BRIDGE_SMTP_LISTEN=:25` for a real MX.
- **Automatic certificates only work on 443.** Let's Encrypt performs its challenge there and
  nowhere else, so the daemon refuses to start if you point `DMCND_LISTEN` somewhere else without
  also supplying `DMCND_TLS_CERT`/`DMCND_TLS_KEY`. Terminating TLS at a proxy is fine — bring your
  own certificate, or run the proxy in front and give the daemon one it can use.

Two daemons on two domains then interoperate the way email already does: resolve the recipient's
domain, dial a seed, fetch the signed record, store the sealed envelope. For a local cluster with
no real DNS, list the peer anchors in a `DMCND_STATIC_DNS` file instead — the resolver checks it
before DNS, so you can exercise the whole path offline.

## Configuration

Everything is environment-driven. These are the ones you'll actually touch:

| Variable | Default | Purpose |
|---|---|---|
| `DMCND_DOMAIN` | `localhost` | the domain this daemon serves |
| `DMCND_LISTEN` | `:443` (`:8080` in dev) | webmail listen address |
| `DMCND_NODE_LISTEN` | `/ip4/0.0.0.0/tcp/7400` (ephemeral in dev) | libp2p listen address — the port in your published `seed=` |
| `DMCND_DATA_DIR` | `data` | mailboxes, records, the node key |
| `DMCND_IDENTITY` | `<data-dir>/node.key` | libp2p identity — keeps the peer ID stable across restarts |
| `DMCND_PETITION_TTL` | `24h` | how long an unclaimed mailbox petition survives |
| `DMCND_DEV` | `false` | plain HTTP on localhost, local root key, stubbed DNS anchoring |
| `DMCND_PEERS` | — | peers to bootstrap from |
| `DMCND_BRIDGE_ENABLED` | `false` | turn on the SMTP bridge |
| `DMCND_BRIDGE_DELIVERY_MODE` | `stub` | `smtp` to actually send outbound mail (default captures it in memory) |

The full list — TLS, libp2p listen addresses, federation allow-sets, bridge options — is in
the [repository README]({{repo}}#configuration-dmcnd_-environment).

Note the federation default: **deny**. Outside dev mode a node admits no peers until you
either allowlist them or hand them a valid credential.

## The SMTP bridge

A bridge is **infrastructure, not a correspondent**. It has no mailbox and no address you can
send to: it is your node, wearing a second hat, holding a credential from your domain root that
says it may vouch for legacy mail. That credential is the only thing that makes anything it says
believable, so issue it first — offline, alongside the rest of the ceremony:

```bash
# [admin] one signature over the node's own public key. The peer ID is enough: an Ed25519 peer
# ID contains its key, so this needs no contact with the node.
dmcndcli bridge issue --domain mesh.example --peer <peer-id> --keystore root.enc --out bridge.cred

# [node]
DMCND_BRIDGE_ENABLED=true DMCND_BRIDGE_CREDENTIAL=/path/to/bridge.cred dmcnd
```

Inbound legacy mail gets checked with real SPF/DKIM/DMARC at the bridge, and the verdict travels
as a signed attachment *inside* the sealed envelope, together with that credential. The
recipient's client verifies three things without asking any server anything: the verdict is
signed by the key it names, that key holds a `bridge` credential from the domain root, and the
credential is *for that key* — so a real bridge's credential cannot be stapled to someone else's
attestation.

Start the bridge without a credential and it still relays mail, but every recipient will treat
its verdicts as unverified. The daemon says so at startup rather than letting you find out from
someone else's inbox.

Outbound — your users writing to ordinary email addresses — needs one more thing: a `bridge=`
token in your `_dmcn` record, so a sender can find out which peer carries mail off the network.
It is the DMCN analogue of an MX record, and usually the same address as your `seed=`:

```bash
dmcndcli domain dns --domain mesh.example \
  --seed /ip4/<public-ip>/tcp/7400/p2p/<peer-id> \
  --bridge /ip4/<public-ip>/tcp/7400/p2p/<peer-id>
```

DNS only *discovers* the bridge; the credential decides whether to use it. A sender resolves the
`bridge=` endpoint, fetches that peer's signed descriptor, and checks it carries a `bridge`
credential from your domain root before sealing anything to it. That check is not a formality: a
relay only ever holds sealed envelopes, but a bridge decrypts outbound mail in order to hand it to
SMTP, so whoever answers a `bridge=` token reads the plaintext. Poisoning your DNS is not enough to
become that peer.

Actually sending is still opt-in and off by default:

```bash
DMCND_BRIDGE_ENABLED=true DMCND_BRIDGE_CREDENTIAL=bridge.cred \
  DMCND_BRIDGE_DELIVERY_MODE=smtp DMCND_BRIDGE_DKIM_KEY=dkim.pem dmcnd
```

Without `DMCND_BRIDGE_DELIVERY_MODE=smtp` the bridge accepts and translates outbound mail but
captures it in memory instead of sending it, so installing the daemon never starts emitting live
mail at anyone. Turn it on and you want a DKIM key too — unsigned mail from a new host is filtered
almost everywhere.

**The honest bits.** Mail crossing a bridge is TLS-in-transit on the legacy side, not end-to-end
encrypted — and outbound is worse than that phrase suggests: the bridge *decrypts* your message to
hand it to SMTP, so it reads the plaintext. The compose window says so when a recipient is not a
DMCN address. A bridge is there for interoperability, not security, and mail that stays inside DMCN
never leaves the sender's device unsealed. And SPF, DKIM and DMARC are only meaningful if the DNS
they read is real — `DMCND_BRIDGE_AUTH_MODE=stub` exists for offline development and turns the
verdict into a rubber stamp, so never run it anywhere real mail arrives.
