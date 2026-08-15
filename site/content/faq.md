---
title: FAQ
description: Common questions about the DMCN Protocol — how it differs from encrypted email, why there is no DHT, what a relay operator can and cannot do, and what is core versus extension.
---

# Frequently asked questions

## How is this different from encrypting email?

PGP and S/MIME encrypt the *body* of a message that still travels over SMTP, so they
inherit SMTP's trust model: the addressing layer stays unauthenticated, metadata stays in
the clear, and whether a message is trustworthy is decided by filters and reputation after
the fact.

DMCNP moves the cryptography down a layer. The address *is* a keypair, so authenticity is a
property of the identity rather than a verdict about a message. There is no unauthenticated
addressing layer left to spoof, and both the header and the body travel sealed.

## Is there a blockchain, a DHT, or a global directory?

No — and the absence of one is a deliberate design decision rather than an omission.

An earlier iteration did resolve identities through a Kademlia DHT. It was removed because a
sufficiently resourced hostile majority in a global overlay can withhold or censor records.
For a system meant to replace email, that is an availability flaw serious enough to
disqualify the design.

Resolution is now per-domain and DNS-seeded: read `_dmcn.<domain>`, dial that domain's own
fleet, verify what comes back against the fingerprint from DNS. A domain is served only by
its own fleet, never by a global overlay a foreign majority could block.

## What if a domain's fleet lies about a record?

It cannot, in the sense that matters. Records are **self-certifying** — signed by the
identity's own key and chained to a domain authority anchored by the fingerprint in DNS. A
hostile or simply wrong fleet can refuse to answer, or answer with something that fails
verification, and both outcomes are denial of service. Neither is forgery.

This is why the trust anchor lives in DNS and the records live with the domain: the two
failure modes stay separate, and the dangerous one is unavailable.

## Can my provider move my mailbox without asking me?

Yes — deliberately. The `RelayHints` that say which relays hold your mailbox sit *outside*
your self-signature, carried in an operator-signed routing credential. An operator can
re-point them to rebalance load or drain a machine without ever touching your key.

What an operator cannot do is change who you are. The identity core — your address, your
keys, your validity window — is covered by your own signature, so re-pointing routing moves
the mailbox without moving the identity. Your address never changes, which is also what
makes portability work.

## Who can read my mail?

All cryptography is client-side. Relays only ever handle sealed envelopes: a per-message
AES-256-GCM content key, wrapped to each recipient device over X25519, with the header and
body sealed separately so that listing an inbox never touches a body.

Two honest limits. Mail that crosses the **SMTP bridge** is TLS-in-transit on the legacy
side, not end-to-end encrypted — a bridge is an interoperability affordance, not a security
boundary. And relays necessarily see routing metadata: which mailbox is receiving something,
and roughly when. Payloads are padded to size-class buckets to blunt traffic analysis, and
onion routing exists for senders who need the path itself concealed.

## What is "core" and what is an "extension"?

The core is what an independent implementation needs in order to interoperate: resolve,
verify, send, receive. Everything else — fleet administration, hosting permits,
provisioning, entitlements, relay-assisted client conveniences — is an extension.

Extensions attach through surfaces the core designs for them: separate libp2p protocol IDs,
operator-attached credentials, and `ext.`-prefixed credential attributes. They never attach
through new core fields. The rule that makes the split meaningful is that **an
implementation which ignores every extension still interoperates fully** — extensions may
add operator capability, never an interop requirement.

## Why are some field numbers reserved?

Because they were used once. Vacated field and arm numbers carry `reserved` declarations
with gravestone comments, and they are never reused. Several belonged to operator surfaces
that moved out of the core when the extension boundary was drawn.

Reusing a number would silently mis-decode messages from an older peer, so the history is
part of the schema.

## How do I implement DMCNP in another language?

Start from [the specification](/spec), and treat `proto/` in the reference implementation as
the authoritative schema — the spec is prose about those files, and where they disagree the
schema and the implementation win.

The parts worth reading closely first are the signing convention (every signature is over
deterministic protobuf with the signature field cleared, under a per-type context tag), the
resolution flow, and the challenge-response that authorizes a fetch. Optional capabilities —
onion routing and the SMTP bridge — can be left out entirely without affecting interop.

## Is it decentralized if domains still have operators?

It is federated, and it is worth being precise about what that does and does not give you.
Operators run relays, hold routing, and may attest addresses on their domain — that is real
power over availability and over routing.

What they never hold is the ability to read your mail or to impersonate you, because the
keys that would let them do either never leave your device. The design goal is not the
absence of operators; it is that choosing one grants them the smallest possible amount of
authority, and that leaving takes nothing away from you but a routing change.

## Is it production ready?

No. The reference daemon is a proof of concept — embedded stores, dev-oriented defaults, no
operational hardening — and the specification is a snapshot versioned with it rather than a
frozen standard. It is complete enough to interoperate against and to read as the executable
half of the spec; it is not something to put in front of real users today.

## What does the license allow?

Apache-2.0, including an express patent grant with defensive termination: you may implement
this protocol without fear of patent assertion by its authors, and that grant terminates for
anyone who initiates patent litigation over it.

The license covers the code and the schema. It does not grant rights to the names **DMCN**
or **DMCN Protocol**, so implement freely under a name of your own — and describe something
as speaking DMCNP only when it genuinely conforms.
