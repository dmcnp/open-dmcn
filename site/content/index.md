---
title: The DMCN Protocol
description: DMCNP is an open protocol for end-to-end-encrypted mail, where the address is a keypair instead of a name a server vouches for. Apache-2.0 spec and schema.
tagline: An open protocol for end-to-end-encrypted mail. Your address is a keypair. Your domain serves its own records, found through DNS. There's no global directory to censor, and no server that can read your mail.
---

## Start with the schema

The protocol is four `.proto` files. They define identity records, credentials, the message
envelope, and the relay wire format — and they're the contract, not the prose. If the
[spec](/spec) and the schema ever disagree, the schema wins.

Everything else on this site exists to explain them.

## Two names

**DMCN** is the network — the deployments that actually exchange mail. **DMCNP** is what
they speak, and that's what's specified here.

Implement it under any name you like. Apache-2.0 covers the code and the schema, patent
grant included. Just don't call something DMCNP unless it really conforms — the name is
how people know what they're getting.

## Why there's no global directory

Most decentralised messaging puts identity in a shared overlay: a DHT, a chain, a consensus
set. DMCNP doesn't, and the reason is boring rather than ideological. A big enough hostile
majority in a shared overlay can quietly withhold records. For something meant to replace
email, that's fatal.

So resolution works like mail delivery already does. A domain publishes a `_dmcn` TXT
record with its trust anchor and a few seed nodes. You read it, dial that domain's own
nodes, fetch the signed record, and check it against the anchor from DNS.

A domain is served by its own nodes and nobody else's. Records sign themselves, so a
hostile server can refuse to answer you — it can't lie to you.

## Where it's up to

This is a snapshot, not a frozen standard. The schema moves with the reference
implementation, and the implementation wins where they disagree. Formal versioning and a
conformance suite aren't done yet.

The wire schema is the compatibility contract. Everything under `internal/` is just how one
implementation happens to work, and carries no stability promise.
