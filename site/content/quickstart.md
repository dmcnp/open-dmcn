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

### What follows the account

Your **mail** lives in the mailbox on the relay. So does the state that goes with it — contacts,
Sent, read/unread, labels and settings — kept in the relay's personal storage. Sign in on a phone
and both are there.

Everything in that store is **sealed to you in the browser before it is sent**. The relay holds
ciphertext it has no key for; it can count your bytes and hand the blobs back, and that is all.
That is what makes it reasonable to keep an address book on a server at all, and it is the same
posture as your mail, which the relay is already storing sealed.

A relay is not obliged to offer storage — a minimal one can serve mail and nothing else. It says
so, and the client keeps that state in the browser instead: single-device, still working.

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

### Ports — open these first

Do this before starting anything. Two of the steps below reach the node over the network, and a
closed port shows up as a timeout four steps after the mistake was made.

**Inbound — these are the firewall rules to add:**

| Port | What for | When |
|---|---|---|
| `7400` (`DMCND_NODE_LISTEN`) | libp2p: federation with other domains, and the `domain publish` step below. **This is the port in your published `seed=`.** | any live domain |
| `443` (`DMCND_LISTEN`) | webmail, and the ACME challenge for its certificate | always |
| `25` | SMTP — your domain's MX | bridge enabled |

**Outbound — already fine unless you filter egress:**

| Port | What for | When |
|---|---|---|
| `53` | DNS: other domains' `_dmcn` records, and MX/SPF/DKIM/DMARC lookups | always |
| `25` | delivering to other providers' mail servers | `DELIVERY_MODE=smtp` |
| ephemeral | dialling other domains' seeds and bridges | always |

Three of these catch people out:

- **Automatic certificates only work on 443.** Let's Encrypt performs the TLS-ALPN-01 challenge
  there and nowhere else, so the daemon refuses to start if you point `DMCND_LISTEN` elsewhere
  without also supplying `DMCND_TLS_CERT`/`DMCND_TLS_KEY`. Terminating TLS at a proxy is fine —
  bring your own certificate. There is no DNS-01 challenge and nothing here runs a DNS server, so
  you do not need inbound `53` or an acme-dns sidecar.
- **Many hosting providers block outbound port 25 by default** and want a support ticket before
  they will open it. A bridge that receives fine but never delivers is usually this, not a DMCN bug.
- **Inbound 25 and 443 need privileges** (`setcap CAP_NET_BIND_SERVICE`, or systemd
  `AmbientCapabilities`). The bridge's own default is `:2525`, which is convenient for testing and
  which no sending mail server will ever try — set `DMCND_BRIDGE_SMTP_LISTEN=:25` for a real MX.

**1. [node]** Install the daemon and get its peer ID. Set the libp2p port first — it goes into DNS
and is awkward to change later — and confirm 7400 is reachable from wherever you will run
`dmcndcli`, since step 7 dials it.

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
  --keystore root.enc
```

It asks for a passphrase — twice, since this one is being set — and prints the DNS record. Every
later command that needs the root asks the same way. Three ways to supply it, and the difference
between them is where the secret ends up:

| | Ends up in |
|---|---|
| type it when asked | nowhere |
| `DMCND_ROOT_PASSPHRASE=…` | the environment |
| `--passphrase …` | the environment, your shell history, **and `ps`** |

Scripting it is fine — prefer the variable, since a value in `argv` is readable by anyone else on
the machine for as long as the command runs. `DMCND_ROOT_PASSPHRASE="$PASS" dmcndcli …` is the same
command with the flag dropped.

The authority record it signs sets two things that are easy to miss and
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

**If the node is behind NAT.** A cloud VM whose public IP is NAT'd rather than on an interface
binds a private address, and libp2p can only see what it binds — so the node would advertise
`10.x` to the world. That address is written into the RelayHints of every mailbox it provisions,
so other domains would be told to deliver your mail somewhere unreachable, and nothing local would
notice. Set `DMCND_ANNOUNCE_ADDR=/ip4/<public-ip>/tcp/7400` and it advertises that instead. To
check: after assigning yourself a mailbox, look at the `relay_hints` on your published record — if
they are private addresses, this is why.

**Serving the client on a subdomain.** Addresses come from `DMCND_DOMAIN`, but the client does not
have to be served there. Set `DMCND_WEB_HOST=mail.example.com` and webmail is served — and
certificated — on that name while addresses stay `user@example.com`, the arrangement ordinary email
has always had. Point the subdomain at the node; the apex only needs the `_dmcn` TXT record. Both
names are whitelisted for autocert, so the apex keeps working if you point it here too.

**6. [node]** Start the daemon.

```bash
# Once, so it may bind :443 as an ordinary service user — see Ports above.
sudo setcap CAP_NET_BIND_SERVICE=+eip "$(command -v dmcnd)"

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
    --url https://mesh.example  --keystore root.enc
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

## Configuration

Everything is environment-driven. These are the ones you'll actually touch:

| Variable | Default | Purpose |
|---|---|---|
| `DMCND_DOMAIN` | `localhost` | the domain addresses belong to (`user@<domain>`) |
| `DMCND_WEB_HOST` | `$DMCND_DOMAIN` | hostname the web client is served on, if not the domain itself |
| `DMCND_LISTEN` | `:443` (`:8080` in dev) | webmail listen address |
| `DMCND_NODE_LISTEN` | `/ip4/0.0.0.0/tcp/7400` (ephemeral in dev) | libp2p listen address — the port in your published `seed=` |
| `DMCND_ANNOUNCE_ADDR` | detected | where other domains should reach this node, if that is not the address it binds (NAT) |
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

Actually sending is still opt-in and off by default, and wants a DKIM key. Generate one and
publish what it prints — the command outputs the whole SPF/DKIM/DMARC set:

```bash
dmcndcli bridge dkim-keygen --domain mesh.example --host mail.mesh.example \
  --ip <public-ipv4> --ip <public-ipv6> --out dkim.pem
```

**`--domain` is the domain mail is *from*, not the host it runs on.** If addresses are
`user@mesh.example` then `d=mesh.example`, even when the bridge and the webmail live on
`mail.mesh.example`. DMARC compares `d=` against the `From:` header, and the bridge rewrites
`From:` to `@<domain>` — so putting DKIM on the subdomain makes every message fail DMARC while
looking perfectly configured. The two roles split like this:

| | Name | Records |
|---|---|---|
| the **domain** mail is from | `mesh.example` | SPF, DKIM (`d=`), DMARC |
| the **host** running the bridge | `mail.mesh.example` | MX target, EHLO, PTR |

The daemon takes the host from `DMCND_WEB_HOST` (then the domain) for its EHLO name, so on a
subdomain setup this is already right. It deliberately never falls back to the machine's own
hostname: on a VPS that is something like `ubuntu-2gb-hel1-1`, which is not a FQDN, has no A
record, and will not match your PTR — and receivers penalise a HELO that does not resolve.
`DMCND_BRIDGE_HELO` overrides it if the sending host is neither.

`--host` sets the second (defaults to the domain, for a single-name setup). `--ip` is repeatable
and fills in the SPF and PTR lines; each address is classified into `ip4:`/`ip6:` for you, and an
SPF mechanism like `include:_spf.example.net` is passed through untouched.

**Include IPv6 if the host has it.** Outbound SMTP dials `tcp`, so Go prefers IPv6 whenever the
receiving MX has an AAAA record — mail really does leave over v6, and an `ip4`-only SPF record
fails for exactly those messages. Intermittently, since it depends on the receiver. Every address
you send from also needs its own PTR.

It prints the full set:

```
  merten.vg.                  IN MX   10 mail.merten.vg.
  merten.vg.                  IN TXT  "v=spf1 ip4:203.0.113.7 ip6:2001:db8::7 -all"
  dmcn._domainkey.merten.vg.  IN TXT  "v=DKIM1; k=rsa; p=MIIBIjANBg…"
  _dmarc.merten.vg.           IN TXT  "v=DMARC1; p=quarantine; …"
  ; plus the PTR requirement, which is set at your provider, not in this zone
```

Then:

```bash
DMCND_BRIDGE_ENABLED=true DMCND_BRIDGE_CREDENTIAL=bridge.cred \
  DMCND_BRIDGE_DELIVERY_MODE=smtp DMCND_BRIDGE_DKIM_KEY=dkim.pem dmcnd
```

The daemon reprints the same records on startup whenever it is actually sending, so you can check
what you published against what it is signing with. **Publish before you send.** A key whose
selector does not resolve is worse than no key at all: a DKIM signature that fails to verify reads
as forgery, where an absent one merely reads as unauthenticated.

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
