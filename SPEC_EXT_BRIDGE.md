# DMCNP extension: the SMTP bridge

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md).

A bridge carries mail between DMCN and ordinary email. Inbound, it authenticates legacy mail and
signs its verdict; outbound, it decrypts a DMCN message and hands it to SMTP. This document
defines the `bridge` credential role, the two signed records a bridge produces, and how a sender
finds a domain's bridge.

Who needs it: domains that exchange mail with ordinary email, senders that write to legacy
addresses, and readers that want to verify a bridge's verdict on the mail it brings in.

## 1. The bridge

An implementation may operate an SMTP↔DMCN bridge. A bridge is infrastructure, not a
correspondent. It has no DMCN address and no directory entry. It is a peer whose key carries a
`bridge` credential (`SPEC_CORE.md` §2) issued by the domain authority, and that credential is
the whole basis on which anyone believes it.

A bridge maps the legacy sender onto `sender_address` + `sender_display`. The identity it should
carry is the one it authenticated. That is the From header, which DMARC evaluates and a reader
recognises. It is not the SMTP envelope sender, which for bulk mail is a per-message bounce
address that makes every message look like a new correspondent. The envelope sender is preserved
in the classification record below.

Inbound legacy mail is authenticated (SPF/DKIM/DMARC) at the bridge, and the verdict travels as
a signed **`BridgeClassificationRecord`** attachment
(`application/x-dmcn-bridge-classification`) inside the sealed envelope. Outbound delivery
returns a signed **`BridgeDeliveryReceipt`**. Both carry the bridge's `bridge` credential, so a
recipient verifies an attestation with no lookup at all:

1. the record's signature is valid for the key it carries;
2. the attached credential is signed by the domain authority root and grants `bridge`; and
3. that credential's subject is the key that signed the record.

Without step 3, the first two prove nothing. A credential is public, because it travels in every
message the bridge signs, so without binding it to the signer, anyone could attach a real
bridge's credential to their own attestation.

The credential is not covered by `bridge_signature`, and does not need to be: it carries its own
issuer signature, the subject-equals-signer check defeats substitution, and the whole record
rides inside the end-to-end-signed message that delivers it. Covering it would mean a credential
could not be re-issued without invalidating every attestation ever made under it.

`bridge_address` is the bridge's libp2p peer ID. It is informational, for display and logs, and
it is not an address anyone can send to.

**Discovery (outbound).** A domain advertises its bridge with a `bridge=` token in its `_dmcn`
TXT record. The token is a multiaddr including `/p2p/<peerID>`, the DMCN analogue of an MX
record. A sender resolves the token, fetches that peer's self-anchored `RelayDescriptor`
(`SPEC_CORE.md` §6), and requires it to carry a `bridge` credential whose subject is that peer,
before sealing anything to the descriptor's X25519 key.

The DNS token only finds the bridge, and the credential decides whether to trust it. That
separation matters more here than for `seed=`: a relay only ever holds sealed envelopes, but a
bridge decrypts outbound mail to hand it to SMTP, so whoever answers a `bridge=` token reads the
plaintext. A domain that advertises no `bridge=` cannot send outside DMCN.

These records are message payloads, not wire operations: the bridge speaks the same core relay
protocol as everyone else.

Mail crossing a bridge is protected by TLS in transit on the legacy side, and is not end-to-end
encrypted. That TLS is opportunistic, so it is unauthenticated. A bridge should not verify peer
certificates on outbound STARTTLS: SMTP has no trust anchor, so the practical alternative to
unverified TLS is cleartext rather than verified TLS. DANE and MTA-STS are the mechanisms that
make it authenticated, and this specification requires neither.

### Forwarding inbound email

An address's owner may sign a `forward_to` into its identity record (`SPEC_CORE.md` §1). A sender
honours it for native mail. For ordinary email arriving at a bridge for such an address, the
bridge is the only party that can, and a bridge that implements forwarding does the following.
Whether it forwards for a given account at all is the operator's choice. This specification does
not say how the operator records that choice.

- **While the mailbox is open,** the mailbox gets its copy as usual and the target gets another.
  **Once the account is closed** (the mailbox STORE answers `RECIPIENT_CLOSED`), the forward is the
  only copy, so the bridge sends it while the sending server waits at DATA. That outcome is then
  the sender's answer: accepted, a temporary failure to retry, or a permanent one. The bridge
  MUST NOT repeat the target server's reply text to the sender.
- **A target with a DMCN identity** gets the bridged message sealed to it, with the same signed
  classification record, and `recipient_address` set to the target.
- **Any other target** gets the original message bytes over SMTP, with headers only prepended,
  so the original DKIM signature still verifies. The envelope sender is rewritten with SRS onto a
  domain the bridge sends for. A bridge MUST forward as email only a message carrying a DKIM
  signature aligned with its From and no DMARC failure. Forwarding breaks SPF, and without ARC an
  aligned DKIM pass is the only thing the target's own DMARC check can still pass on.
- **One hop.** A forwarded copy carries `X-DMCN-Forwarded: <address>`. A bridge MUST NOT forward a
  message that already carries it, and MUST NOT follow a target's own `forward_to`.
- **Bounces** to an SRS address the bridge minted are accepted and absorbed, never relayed to
  the original sender. Relaying would tell a stranger where a forwarding owner reads their mail,
  and would make the bridge a source of backscatter.

## 2. What a core reader sees

A reader that does not implement this extension still receives bridged mail. The legacy sender's
address does not resolve in DMCN, so the core rule applies (`SPEC_CORE.md` §3): the message is
reported as unverified but not rejected. Such a reader cannot show the bridge's SPF/DKIM/DMARC
verdict, because it does not verify the classification record. The outbound legacy copy names
the legacy recipient while being sealed to the bridge's key, which is the stated exception to
the reader's audience check in `SPEC_CORE.md` §3.

The reference bridge accepts both the split envelope and the legacy non-split one for outbound
mail (`SPEC_CORE.md` Appendix A), since it decrypts the message at once and never stores it.
