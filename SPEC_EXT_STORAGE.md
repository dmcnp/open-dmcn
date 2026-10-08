# DMCNP extension: personal storage

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md).

Who needs it: clients that keep one account's state in step across several devices, and the
relays that hold it for them.

Without it, every client either stays single-device or invents its own incompatible sync, and an
interoperable mail protocol exists to prevent exactly that. Storage does for DMCN what IMAP does
alongside SMTP: it holds the mail together with the state that belongs with it.

## 1. Model

A mailbox holder may keep per-account state on their home relay: contacts, sent messages,
read/unread and labels, client settings. Logical keys are `"<namespace>/<id>"` and the relay
treats them as opaque strings; `MailboxKvList` pages a `"<namespace>/"` prefix.

**Values are sealed to the owner alone.** The relay stores ciphertext for which it holds no key.
It can count bytes and serve blobs back, and that is all. This is the same posture as the
mailbox itself, and it is why storage belongs in the protocol rather than in an operator
extension. A relay that already holds someone's sealed mail is trusted no further by also
holding sealed metadata about it.

Ops ride the same FETCH-authenticated `MailboxOp` stream as `list`/`body`/`delete`
(`MailboxKvGet`, `MailboxKvPut`, `MailboxKvList`, `MailboxKvDelete`, `MailboxKvStat`), so
control of the recipient identity is already proven and every op is scoped to that owner.

A per-key monotonic version supports optional compare-and-swap: `expected_version` non-zero
requires the stored key to be at exactly that version, and a mismatch returns `CONFLICT`. This
is what lets a singleton document edited on two devices resolve rather than silently lose a
write.

Storage is optional for a relay. One that does not offer it answers `UNSUPPORTED`, and a client
is expected to fall back to keeping the state locally. That works, but only on one device. A
relay that does offer it applies its own byte cap per account, covering mail and personal
storage together; `MailboxKvStat` reports the figure actually enforced. Per-account entitlements
are an operator concern and are not part of the protocol (`SPEC_CORE.md` §7).

## 2. Operations

Each is one `MailboxOp` arm, sent after the FETCH challenge exactly like `list`, `body` and
`delete` (`SPEC_CORE.md` §5), one operation per stream:

| Op | Response | What it does |
|---|---|---|
| `kv_put{key, sealed, expected_version}` | `MailboxKvPutResponse{success, version}` | writes one blob; `expected_version` 0 is unconditional, otherwise compare-and-swap |
| `kv_get{key}` | `MailboxKvGetResponse{found, sealed, version}` | reads one blob |
| `kv_list{prefix, limit, cursor, values}` | `MailboxKvListResponse{items, next_cursor}` | pages the keys under a `"<namespace>/"` prefix, with their blobs when `values` is set |
| `kv_delete{key}` | `MailboxKvDeleteResponse{success}` | removes one blob; idempotent |
| `kv_stat{}` | `MailboxKvStatResponse{used_bytes, quota_bytes, count}` | the caller's own usage; `quota_bytes` 0 means no cap |

The relay never inspects `sealed`, and how a client seals it is a matter between that owner's
clients.

Errors: `CONFLICT` (the compare-and-swap version did not match), `QUOTA_EXCEEDED` (the write
would pass the account's cap), `NOT_FOUND`, and `UNSUPPORTED` from a relay that does not offer
storage.
