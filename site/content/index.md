---
title: The DMCN Protocol
description: DMCNP is an open protocol for email that requires every message to be signed by its sender and encrypted to its recipient, with no exceptions. Apache-2.0 spec and schema.
tagline: DMCNP is an open protocol for email. Your address is tied to a key your domain publishes, so anyone can check who sent a message, and only the person it's sent to can read it.
---

## Why it exists

When an email arrives today, the name in the From line is a claim. Your provider checks what it
can, makes a guess, and files the message accordingly, and all you ever see is the guess. That
guessing is why spam filters exist, and why phishing still works.

There have been plenty of fixes on top of email over the years, but SMTP doesn't require any of
them. Each domain decides whether to use them, and each receiving server decides what to do when a
check fails. A check only helps when both ends take part, so in practice mail falls back to
whatever the weakest server on the route supports.

DMCNP starts from the other end. Signing and encryption aren't extras a server can skip. If a
message isn't signed by its sender and sealed to its recipient, it isn't a DMCNP message. You can
still reach people on ordinary email through a bridge, but that mail isn't end-to-end encrypted.

### Why not PGP?

PGP signs and encrypts the body of a message. The subject line and the addresses usually still
travel in the clear, and both people have to make keys and swap them before either can use it. WKD
and OPENPGPKEY let a domain publish its users' PGP keys, but like the rest of PGP they're optional,
and you can't count on finding a key or a signature. Most email still goes without it.
[More in the FAQ](/faq#how-is-this-different-from-encrypting-email).

### Why not S/MIME?

S/MIME signs and encrypts the body of a message using certificates from a certificate authority,
and it's used mostly inside companies. Everyone needs a certificate, issued and renewed per person.
A company can run its own certificate authority, but then anyone outside the company has to trust
that authority before a signature means anything to them. SMIMEA lets a domain publish its users'
certificates in DNS, which solves finding them, but it's an experimental standard and still
optional, for the domain and for the mail app. You can only encrypt to someone whose certificate
you already have, and the subject line and the addresses still travel in the clear.

### Why not SPF, DKIM and DMARC?

SPF, DKIM and DMARC check which domain a message came from, not which person sent it. The provider
decides who may send as which address, and the receiver has to take its word for it. Gmail may stop
its users sending as each other. A less careful provider might not, and the mail passes the same
checks. It's also up to the receiving server whether to act on a failed check, and none of the
three encrypts anything. [More in the FAQ](/faq#what-about-dkim-spf-and-dmarc).

### Why not TLS between mail servers?

TLS encrypts the connection between two mail servers. That protects each hop, but every server
along the way can still read the message. On most routes it's also opportunistic: if the next
server doesn't offer TLS, the mail goes in the clear. MTA-STS and DANE can make it mandatory, but
there's little evidence of domains actually using them.

### Why not use an encrypted email service?

Encrypted email services work well between their own users. Mail to anyone outside falls back to
ordinary email or a link to a web page, so the protection ends at the edge of one company.

## What it is

Your address, say `alice@example.com`, points to a public key that `example.com` publishes and
signs. Every message you send is signed with your key, so whoever receives it can check it really
came from you. It's also encrypted on your device to their key, so the servers that carry it can't
read it.

Finding someone works the way email already does, through DNS. There's no central directory, and
no single company that a message has to pass through.
