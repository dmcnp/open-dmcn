---
title: The DMCN Protocol
description: DMCNP is an open protocol for email that requires every message to be signed by its sender and encrypted to its recipient, with no exceptions. Apache-2.0 spec and schema.
tagline: DMCNP is an open protocol for email. Your address is tied to a key your domain publishes, so anyone can check who sent a message, and only the person it's sent to can read it.
---

## Why it exists

When an email arrives today, the name in the From line is a claim. Your provider checks what it
can, makes a guess, and files the message accordingly, and all you ever see is the guess. That
guessing is why spam filters exist, and why phishing still works.

There have been plenty of fixes on top of email over the years: PGP, S/MIME, DKIM, DMARC,
encrypted connections between servers. Each one is optional, and an optional check only helps
when every server on the route takes part. In practice it falls back to whatever the weakest one
supports.

DMCNP starts from the other end. Signing and encryption aren't extras a server can skip. If a
message isn't signed by its sender and sealed to its recipient, it isn't a DMCNP message. You can
still reach people on ordinary email through a bridge, but that mail isn't end-to-end encrypted.
