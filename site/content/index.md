---
title: The DMCN Protocol
description: DMCNP is an open, peer-to-peer, end-to-end-encrypted mail protocol in which cryptographic identity replaces SMTP-style trust. Specification and Go reference implementation, Apache-2.0.
tagline: An open, peer-to-peer, end-to-end-encrypted store-and-forward mail protocol. Every address is a keypair whose self-certifying record is served by its own domain's fleet and discovered through DNS — so there is no global directory to censor, no authority to petition, and no server that can read your mail.
---

## Two names, two meanings

**DMCN** — the Decentralized Mesh Communication Network — is the *network*: the set of
interoperating deployments that actually exchange mail. **DMCNP**, the DMCN Protocol, is
what they *speak*, and it is what this site specifies.

The distinction matters for a practical reason. You are free to implement DMCNP under any
name you like, and the Apache-2.0 license grants you everything you need to do it —
including an express patent grant with defensive termination. Calling your implementation
"DMCNP" means it genuinely conforms; calling it part of "DMCN" additionally means it
actually interoperates. The license covers the code and the schema; it does not hand over
either name.

## What "no global directory" buys you

Most decentralized messaging designs put identity in a shared overlay — a DHT, a chain, a
consensus set. DMCNP deliberately does not, and the reason is availability rather than
elegance: a sufficiently resourced hostile majority in a global overlay can withhold or
censor records, which is a fatal flaw for something meant to replace email.

Instead, resolution works the way mail delivery already works. A domain publishes a
`_dmcn` TXT record naming its trust anchor and a few seed nodes; a sender reads it, dials
the domain's own fleet, fetches the signed identity record and verifies it against the
anchor from DNS. A domain is served only by its own fleet. Because records are
self-certifying, a wrong or hostile fleet can deny you service — it can never forge an
identity.

## Status

This is a **reference snapshot, not a frozen specification**. The schema is versioned
alongside the reference implementation, which remains authoritative wherever the two
disagree, and the daemon is an honest proof of concept — embedded stores, dev-oriented
defaults — rather than a hardened production deployment. The wire schema is the
compatibility contract; the `internal/` packages carry no API-stability promise.
