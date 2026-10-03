---
title: How the protocol works
description: The DMCN protocol in technical detail: its layers, how an address is resolved, what the core covers, where the protocol is up to, and a field-by-field reference generated from the schema.
---

# How the protocol works

## Overview

DMCNP is seven layers. Speak all of them and you interoperate with the network.

| Layer | What it does |
|---|---|
| User identity | An Ed25519 signing key and an X25519 key-exchange key. The address is `local@domain`, and its record signs itself. |
| Resolution | A `_dmcn.<domain>` TXT record gives you a fingerprint to trust and a few nodes to dial. You fetch signed records from the nodes it names and check them against the fingerprint. |
| Message model | PlaintextMessage, then SignedMessage, then EncryptedEnvelope. One AES-256-GCM key per message, wrapped to each recipient over X25519. Header and body are sealed separately, and both are padded to fixed size classes. |
| Routing | RelayHints say which relays hold a mailbox. They sit outside the owner's signature, so an operator can move a mailbox without the owner's key, and the address never changes. |
| Relay service | `/dmcn/relay/1.0.0`: store, fetch, mailbox operations, record lookups and onion forwarding, as length-prefixed protobuf over libp2p. |
| Trust and federation | Each domain has an authority record, anchored in DNS, that delegates to issuers. Peers exchange and verify credentials at `/dmcn/join` before they federate. |
| Transport | libp2p streams. Discovery is seeded from DNS, with no DHT, on purpose. |

The protocol itself is four `.proto` files, defining identity records, credentials, the message
envelope and the relay wire format. They're the contract. If the [spec](/spec) and the schema
ever disagree, the schema wins, and the reference further down this page is generated from it.

## Why there's no global directory

Most decentralised messaging puts identity in a shared overlay: a DHT, a chain, a consensus set.
DMCNP doesn't, and the reason is practical. A big enough hostile majority in a shared overlay can
quietly withhold records, and for something meant to replace email that's fatal.

So resolution works the way mail delivery already does. A domain publishes a `_dmcn` TXT record
with its trust anchor and a few seed nodes. You read it, dial the nodes it names, fetch the
signed record, and check it against the anchor from DNS.

A domain is served by the nodes its own DNS names: its own, or a host it explicitly delegates to.
It's never served by a shared pool it didn't choose. Records sign themselves, so a server that
isn't your domain's authority can refuse to answer you, but it can't lie to you.

## Core and extensions

The core is what you need to interoperate: resolve an address, verify an identity, send mail and
receive it. Two capabilities are optional and can be skipped entirely: onion routing, and an SMTP
bridge to ordinary email.

Anything an operator wants but the network doesn't need is an extension: fleet administration,
hosting permits, entitlements, quotas. Extensions attach through surfaces the core sets aside for
them, never through new core fields.

The rule that split protects: ignore every extension and you still interoperate. An extension can
give an operator new powers. It can never make your implementation stop working with the network.
Retired field numbers stay `reserved` forever.

## Status

This is a snapshot of the reference implementation, not a frozen standard. The schema moves with
the implementation, and where this site and the implementation disagree, the implementation wins.
Formal versioning and a conformance suite are on the roadmap and aren't done yet.

The wire schema is the compatibility contract. Everything under `internal/` in the repository is
how one implementation happens to work, and carries no stability promise.

## Licence

Apache-2.0 covers the code and the schema, with an express patent grant. It doesn't cover the
names: implement the protocol under whatever name you like, but don't call something DMCNP unless
it really conforms. The [FAQ](/faq#what-does-the-license-allow) has the detail.
