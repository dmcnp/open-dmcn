---
title: The trust model
description: Who DMCNP asks you to trust, and for what. Mailbox users, domain operators and fleet operators each hold their own keys, every link between them is signed, and the recipient's app checks each one back to a DNS anchor.
---

<figure>
  <a href="/static/img/trust-model.svg"><img src="/static/img/trust-model.svg" width="1920" height="1080" alt="The DMCN trust model in three layers. Mailbox users hold their own keys on their own devices. Domain operators each anchor a domain in a _dmcn DNS record and an offline root key, and vouch for their users' addresses. Fleet operators each anchor a fleet the same way and vouch for their relays and bridges. Domains name the fleet that hosts them. Mail from a user on one fleet goes straight to the recipient's relay on another, signed with the sender's key; fleets need no trust between them. Ordinary email is reached only through a bridge, and that link is unsigned."></a>
</figure>
