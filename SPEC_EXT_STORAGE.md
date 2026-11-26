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
treats them as opaque strings; `MailboxKvList` pages a `"<namespace>/"` prefix. There is one
exception to "opaque", in §3.

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
| `kv_get{key}` | `MailboxKvGetResponse{found, sealed, version, written_at, sealed_writer}` | reads one blob, with the relay's marks (§4) |
| `kv_list{prefix, limit, cursor, values}` | `MailboxKvListResponse{items, next_cursor}` | pages the keys under a `"<namespace>/"` prefix, with their blobs and marks when `values` is set |
| `kv_delete{key}` | `MailboxKvDeleteResponse{success}` | removes one blob; idempotent |
| `kv_stat{}` | `MailboxKvStatResponse{used_bytes, quota_bytes, count}` | the caller's own usage; `quota_bytes` 0 means no cap |

The relay never inspects `sealed`, and how a client seals it is a matter between that owner's
clients.

Errors: `CONFLICT` (the compare-and-swap version did not match), `QUOTA_EXCEEDED` (the write
would pass the account's cap), `NOT_FOUND`, and `UNSUPPORTED` from a relay that does not offer
storage.

## 3. Names a relay knows

A relay that keeps a device registry lets an enrolled device write some keys without the
account's signature ([`SPEC_EXT_DEVICES.md`](SPEC_EXT_DEVICES.md) §3), and it tells them apart by
name. That makes these names protocol, and a client that keeps this state uses them:

| Key | What a client keeps there |
|---|---|
| begins `drafts/` | one row per unsent message |
| begins `draft-body/` | its text |
| begins `draft-att/` | its attachments |
| begins `flags/` | one record per message: read, starred, archived, folder, labels, trashed |
| is exactly `settings/labels` | the names of the owner's labels and folders |

Every other key stays opaque to a relay, and how a client lays out the rest is its own choice.

## 4. What the relay records about a write

A value is sealed, so a relay can't vouch for anything inside it. Two things about a write it
can vouch for, and it keeps them beside the entry:

- **`written_at`**: the relay's clock, in Unix seconds, when this version was written. The writer
  can't set it. A client that acts on how long ago something happened (clearing out trashed mail
  after a waiting period, say) counts from this and never from a time inside the value. A later
  write to the same key moves it forward.
- **`sealed_writer`**: which device signed the write, for a write that carried a device proof.
  The relay seals the device's 32-byte public key to the owner's X25519 key, in the same sealed
  form as a value, and keeps no readable copy. Who wrote what is readable only by someone holding
  the account's key. The relay does see the device key at the moment of the write.

`kv_get` returns both. `kv_list` returns them when `values` is set. `written_at` is `0` on an
entry written before the relay recorded it, and `sealed_writer` is empty where the write carried
no device proof.

Both count toward the account's storage: a mark adds a few hundred bytes to an entry.

A relay that records them advertises `kv-write-time` in `PingResponse.capabilities`. Where an
address has several relays, a write that is copied between them keeps the marks of the relay that
accepted it, so each answers with the same time.
