---
title: FAQ
description: Common questions about the DMCN Protocol — how it differs from encrypted email and from SPF/DKIM/DMARC, why there's no DHT, what a relay operator can and can't do, and what counts as core.
---

# Questions

## What do I actually need to implement?

Four things: resolve an address, verify an identity, send mail, receive mail.

Start with `proto/` in the repository — that's the real contract. Then read [the spec](/spec)
for the parts the schema can't express: the signing convention, the resolution flow, and the
challenge-response that authorises a fetch.

Onion routing and the SMTP bridge are optional. Skip them and you still interoperate.

## How is this different from encrypting email?

PGP and S/MIME encrypt the body of a message that still travels over SMTP. So they inherit
SMTP's problem: the addressing layer is unauthenticated, metadata is in the clear, and
whether a message is trustworthy gets decided after the fact by filters and reputation.

DMCNP moves the crypto down a layer. The address *is* a keypair, so authenticity is a
property of the identity rather than a verdict about a message. There's no unauthenticated
addressing layer left to spoof, and the header travels sealed alongside the body.

## What about DKIM, SPF and DMARC?

They're the best answer SMTP has, they genuinely help, and DMCNP is not pretending otherwise.

What they do: SPF says which servers may send for a domain. DKIM signs a message with a
domain's key. DMARC ties the From address you actually see to one of those two, and tells
receivers what to do when they don't line up.

Three things that leaves open.

**They authenticate a domain, not a person.** A valid DKIM signature says "a server
authorised by example.com sent this". It doesn't say which account, and it can't — the
signing key belongs to the provider, not to you. Anyone who can send through that provider
inherits the same signature.

**Enforcement is the receiver's choice.** DMARC is a request, not a rule. A domain can
publish `p=reject` and a receiver can deliver the mail anyway — plenty do, because strict
enforcement breaks forwarding and mailing lists. The guess doesn't disappear; it moves.

**They say nothing about the contents.** These are authentication, not confidentiality. The
message is still readable by every server that handles it, and sits in the clear at both
ends.

DMCNP moves the key to the person. Your signature is made on your device, with a key your
provider never holds, so who sent a message is settled by the message itself rather than by
a policy the receiving side may or may not honour. The same key is what lets the mail be
sealed so the servers in between can't read it either.

None of which makes the old three useless. DMCNP's [SMTP bridge](/quickstart) runs all of
them on inbound legacy mail and passes the verdict on as a signed attestation inside the
sealed envelope — for mail that starts in the old world, they're the best signal there is.

## Is there a blockchain, a DHT, or a global directory?

No, and that's deliberate.

An earlier version did resolve identities through a Kademlia DHT. It came out because a big
enough hostile majority in a shared overlay can quietly withhold records. For something
meant to replace email, that's disqualifying.

Resolution is per-domain and DNS-seeded now: read `_dmcn.<domain>`, dial that domain's own
nodes, check what comes back against the fingerprint from DNS. A domain is served by its own
nodes and nobody else's.

## What if a domain's server lies about a record?

It can't, in the way that matters. Records sign themselves, and they chain to a domain
authority anchored by a fingerprint in DNS. A hostile or just broken server can refuse to
answer, or answer with something that fails verification. Both mean you don't get service.
Neither means you get a forgery.

That's the whole reason the anchor lives in DNS and the records live with the domain: the
dangerous failure isn't available.

## Can my provider move my mailbox without asking me?

Yes, on purpose. The `RelayHints` that say which relays hold your mailbox sit *outside* your
signature, in a credential the operator signs. So an operator can re-point them to rebalance
load or drain a machine without touching your key.

What they can't do is change who you are. Your address, your keys, your validity window —
those are covered by your own signature. Moving the mailbox doesn't move the identity, which
is also why your address survives the move.

## Who can read my mail?

All the crypto happens client-side. Relays only ever handle sealed envelopes: one AES-256-GCM
key per message, wrapped to each recipient over X25519, with the header and body sealed
separately so listing an inbox never touches a body.

Two honest limits. Mail crossing the **SMTP bridge** is TLS-in-transit on the legacy side,
not end-to-end encrypted. And relays necessarily see routing metadata — which mailbox is
getting something, and roughly when. Payloads are padded to fixed size classes to blunt
traffic analysis, and onion routing is there for senders who need the path hidden too.

## What's core and what's an extension?

Core is what you need to interoperate. Everything else — fleet administration, hosting
permits, provisioning, entitlements, quotas — is an extension.

Extensions attach through surfaces the core designs for them: separate libp2p protocol IDs,
operator-attached credentials, `ext.`-prefixed credential attributes. Never through new core
fields.

The rule that makes the split mean anything: **ignore every extension and you still
interoperate**. An extension can give an operator new powers. It can't add a requirement to
the network.

## Why are some field numbers reserved?

Because they were used once. Retired field and arm numbers keep a `reserved` declaration and
a comment saying what they were, and they never get reused — several belonged to operator
surfaces that moved out when the core/extension line got drawn.

Reuse one and you'd silently mis-decode messages from an older peer, so the history is part
of the schema.

## Is it decentralised if domains still have operators?

It's federated, and it's worth being precise about what that buys you.

Operators run relays, control routing, and can attest addresses on their domain. That's real
power over whether you get service and where your mail sits.

What they never get is the ability to read your mail or impersonate you, because the keys for
either never leave your device. The goal isn't a world with no operators. It's that picking
one hands them as little as possible, and leaving costs you a routing change and nothing
else.

## Is it production ready?

No. The reference server is a proof of concept, and the spec is a snapshot that moves with it
rather than a frozen standard. It's complete enough to interoperate against and to read as
the executable half of the spec. It isn't something to put in front of real users yet.

## What does the license allow?

Apache-2.0, with an express patent grant and defensive termination: implement it without
worrying about patent claims from its authors, and that protection goes away for anyone who
starts patent litigation over it.

The license covers the code and the schema, not the names **DMCN** and **DMCN Protocol**.
Build whatever you like under your own name — just don't call it DMCNP unless it really
conforms.
