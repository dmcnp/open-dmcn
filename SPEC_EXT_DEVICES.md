# DMCNP extension: devices

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md).

The core proves who owns a mailbox with one signature from the account key, so anyone holding a
copy of that key can open the mailbox. This extension adds a second requirement. A mailbox keeps a
registry of enrolled devices, each with a signing key generated on that device, and once a mailbox
has one, every request needs a signature from an enrolled device. Reading the mailbox and keeping
it in order need nothing more. Everything else needs the account key's signature as well. It also
defines pairing, which is how a new device gets approved and receives the account keys.

Who needs it: relays that want a stolen account key alone to be useless against a mailbox, and
clients of those relays. A relay that keeps no registry ignores the device fields
(`SPEC_CORE.md` §5), and a client that finds no registry carries on without one.

## 1. What it costs, and what it does not do

**It is enforced by the relay.** The registry is access control, not cryptography. Mail is sealed
to the account's X25519 key, so someone holding both that key and a copy of the relay's storage can
read it with no device at all. The registry stops a stolen key being used against a relay that is
behaving. It does not protect against the relay.

**It covers reading and mailbox state, not all sending.** See §9.

**An enrolled device can read and organise without the account's signing key.** That is deliberate
(§3): it is what lets a device hold the key that opens mail and not the key that signs it. The cost
is that such a device, or anyone who takes it over, can fetch the mailbox's ciphertext and can
rewrite drafts, read state, folders and labels. It can't send, delete mail, or change who is on
the mailbox.

**A backup stops being enough.** The account key alone no longer opens a mailbox that has devices.
An owner who restores a backup onto a new device needs approval from a device they still have, or
waits out the recovery delay (§4). Domains that turn recovery off accept that an owner who loses
every device loses the mailbox, short of an operator ceremony.

## 2. Device keys

A device key is an Ed25519 key generated on the device. It never leaves the device, and it is not
part of any backup or pairing payload. Clients SHOULD make it non-exportable where the platform
allows.

Clients SHOULD use a separate device key for each account. One key across accounts would show a
relay the same public key on each, and link identities the owner keeps apart.

## 3. The mailbox gate

The device signature says the request comes from somewhere the owner approved. The account
signature says the holder of the account's signing key is asking. Every request to a mailbox that
has devices needs the first. Which requests also need the second depends on the operation.

`FetchProof` and `MailboxOp` carry `device_ed25519_public_key` and `device_signature`. The device
signs `dmcn-device-challenge-v1\0 || nonce`, where `nonce` is the 32-byte challenge of this
exchange.

### Two classes of operation

**Class A: a device signature is enough.** These read the mailbox, or change state the owner can
change back.

| Operation | Limit |
|---|---|
| `list`, `body` | none |
| `kv_get`, `kv_list`, `kv_stat` (`SPEC_EXT_STORAGE.md`) | none |
| `kv_put` | only where the key is in the write list below |
| `kv_delete` | only where the key is in the delete list below |

| Key | `kv_put` | `kv_delete` | What clients keep there |
|---|---|---|---|
| begins `drafts/` | yes | yes | one row per unsent message |
| begins `draft-body/` | yes | yes | its text |
| begins `draft-att/` | yes | yes | its attachments |
| begins `flags/` | yes | no | one record per message: read, starred, archived, folder, labels, trashed |
| is exactly `settings/labels` | yes | no | the names of the owner's labels and folders |

A relay matches these byte for byte, with no case folding and no normalising. `settings/labels` is
one key, not a prefix: every other key under `settings/` is class B.

**Class B: the account signature and a device signature.** Everything else, including:

- `delete`, which removes a message for good;
- `kv_put` and `kv_delete` on any key not listed above;
- `device_enroll` (with the exemption below), `device_list` and `device_retire` (§6);
- the drain FETCH, where a `FetchProof` is answered with every pending envelope
  (`SPEC_CORE.md`, Appendix A).

An operation defined by another extension is class B unless that extension says it is class A.

### The rules

A relay that keeps a registry applies these in order. Every path to a mailbox goes through the
same check, whichever stream or service carried the request:

1. An account signature that is present has to verify, on any operation. A bad one is refused
   with `AUTH_FAILED` and is never ignored.
2. If the mailbox has **never held a device**, the request is answered on the account signature
   alone, whatever its class. There is no device to sign, and the first enrolment (§4) needs the
   account key.
3. Otherwise the request needs a proof from an active device (§4) that verifies. Without one it
   is refused with `DEVICE_NOT_ENROLLED`, and that includes a mailbox whose devices have all been
   retired. If the registry cannot be read and the request brought no valid proof, it is refused.
4. A class B operation also needs the account signature over the challenge. Without it the
   request is refused with `AUTH_FAILED`.
5. On a class A operation the account signature MAY be left empty.

Rule 1 turns on the registry's history, not on who is active. A registry that only holds retired
devices is still claimed, or removing devices would reopen the mailbox to the account key.

There is no switch to flip: the gate starts for a mailbox at its first enrolment.

`device_enroll` is exempt from rule 3, and still needs the account signature. Without the exemption
no first device could join, and a device approved from elsewhere could not ask.

### What the classes are for

A device holding the account's X25519 key and no Ed25519 key can do everything in class A and
nothing in class B. It reads mail, files it, and leaves drafts. It can't send (§9), delete, or
enrol or retire a device. The line is drawn so that everything on the class A side can be undone
by the owner, and nothing on it speaks for the owner to anyone else.

Two things follow for clients:

- **A client MUST NOT delete a message on the strength of a time held inside a class A value.** A
  client that clears out trashed mail after a waiting period counts that period from the time the
  relay recorded the write (`SPEC_EXT_STORAGE.md` §4), never from a time the writer put in the
  record. Otherwise a device with class A access could backdate the record and have the owner's
  own client delete for it. A relay that applies the two classes MUST record that time.
- **A client that has the account key SHOULD still send a device-only proof for class A.** The
  fewer challenges the account key answers, the less a hostile relay can get signed (§7).

A relay can't tell an owner's own request from one the owner didn't intend, on either side of the
line. The classes bound what a device can do. They do not judge why it did it.

## 4. Joining a mailbox

A device joins in one of three ways. Holding the account key authenticates the request but never
authorises it.

**First device.** A mailbox that has never held a device admits the first one at once. A relay
MUST serialise this check, so two devices racing cannot both be first.

**Approved.** An active device vouches for the newcomer. The approval is signed over the live
challenge (§7), so it can't be saved and spent later. Only a party already on the mailbox can get
that challenge, which is why **the approving device performs the enrolment, not the newcomer**.

An approver must have been on the mailbox for at least 24 hours, unless it is the only active
device. The wait means one wrongly admitted device can't quietly enrol others before the owner
notices it. The exemption means a new user can add a second device on their first day.

**Recovery.** For an owner who has lost every device. The device asks with `recovery` set and joins
as *pending*: it is visible in the registry and can't act until `eligible_at`, which is the time of
the request plus the domain's delay. Any active device can stop it by retiring it (§5).

The delay comes from the DAR's `device_recovery_delay_hours`. `0` means 168 hours, and
`DEVICE_RECOVERY_DISABLED` (`0xFFFFFFFF`) removes this path. A relay that can't read the DAR refuses
recovery rather than guessing.

Recovery must be asked for. A relay MUST NOT treat an unapproved enrolment as a recovery request,
and a client MUST NOT start one without a deliberate action by the person using it. A device that
asked on every sign-in would bury a hostile request among the owner's own.

A device is **active** when it isn't retired and any `eligible_at` has passed.

**The enrolment date** is taken from the first of these that exists:

1. the approver's `approved_at`, covered by its signature;
2. the `issued_at` of a `device` credential supplied at enrolment (`SPEC_EXT_ROTATION.md` §3);
3. the relay's clock.

A relay refuses an `approved_at` that is in the future or earlier than the approver's own enrolment,
so a chain of approvals is never older than its youngest link. Where an approval and a credential
are both present, they must agree to within a few minutes.

The credential is optional. Without one a device gates access normally but can't authorise a key
rotation.

## 5. Leaving a mailbox

A device is retired by a **different** active device, over the live challenge (§7). A device can't
retire itself, and the last active device can't be retired, so a mailbox always keeps one way in.
That guard applies only when the target is active. Retiring a pending device is how a recovery
request is vetoed, and it has to work on a mailbox with one device left.

Retirement leaves a tombstone. The owner can see a removal, and a retired key is refused for good:
a removed device that comes back pairs again under a new key. Retiring a retired device changes
nothing, including the date.

## 6. Operations

Each is one `MailboxOp` arm, one per stream, exactly like `list`, `body` and `delete`
(`SPEC_CORE.md` §5): arms 16 to 18 on `MailboxOp`, answered by arms 38 to 40 on `RelayResponse`.

| Op | Response | What it does |
|---|---|---|
| `MailboxDeviceEnrollOp` | `MailboxDeviceEnrollResponse` | Adds a device (§4). The response carries the record and `genesis`, true if this enrolment created the registry. |
| `MailboxDeviceListOp` | `MailboxDeviceListResponse` | Every device on the mailbox, tombstones and pending devices included. Class B (§3). |
| `MailboxDeviceRetireOp` | `MailboxDeviceRetireResponse` | Retires a device (§5). Class B. |

```proto
message DeviceRecord {
  bytes ed25519_public_key = 1;
  int64 enrolled_at = 2;       // §4
  bytes sealed_label = 3;      // a SealedBlob holding the device's name, sealed to the owner
  int64 retired_at = 4;        // 0 = not retired
  int64 eligible_at = 5;       // 0 = effective at once
  bytes device_credential = 6; // optional
}

message MailboxDeviceEnrollOp {
  bytes ed25519_public_key = 1;
  bytes sealed_label = 2;                 // optional, at most 2048 bytes
  bytes approver_ed25519_public_key = 3;  // empty for a first device or a recovery
  bytes approver_signature = 4;           // §7
  bytes device_credential = 5;            // optional, marshaled Credential
  int64 approved_at = 6;                  // Unix seconds, covered by approver_signature
  bool recovery = 7;
}
message MailboxDeviceEnrollResponse {
  DeviceRecord device = 1;
  bool genesis = 2;
}

message MailboxDeviceListOp {}
message MailboxDeviceListResponse { repeated DeviceRecord devices = 1; }

message MailboxDeviceRetireOp {
  bytes ed25519_public_key = 1;         // the device to retire
  bytes signer_ed25519_public_key = 2;  // the active device asking
  bytes signer_signature = 3;           // §7
}
message MailboxDeviceRetireResponse { DeviceRecord device = 1; }
```

The relay learns a device's public key and its dates, and nothing else. Names are sealed to the
owner: which devices exist is an access decision the relay has to make, and what they're called is
not.

A client tells outcomes apart by code, never by the words of the message:

| Code | Meaning | What the client does |
|---|---|---|
| `UNSUPPORTED` | This relay keeps no registry | Carries on without one |
| `DEVICE_NOT_ENROLLED` | The mailbox has devices and the request brought no proof from an active one (§3) | Offers pairing |
| `DEVICE_ALREADY_ENROLLED` | This key is enrolled | Nothing: this is success |
| `DEVICE_APPROVAL_REQUIRED` | The registry is claimed and this key isn't on it, or it was removed | Offers pairing |
| `DEVICE_ON_PROBATION` | The approver is too new (§4) | Asks for approval from an older device |
| `DEVICE_RECOVERY_DISABLED` | The domain has no recovery path | Says so |
| `AUTH_FAILED` | A signature didn't verify, the approver or signer isn't active, or a class B operation came without the account signature (§3) | Stops |
| `INVALID_REQUEST` | The request is malformed or breaks a rule above | Stops |
| `STORAGE_FAILED` | The registry could not be read or written | Tries again later |

A service that carries these operations for a client (a web host in front of a relay, say) hands
the code on unchanged. It never leaves the client to read the sentence beside it.

**Enrolling is how a client finds out where it stands.** Listing needs an enrolled device and the
account key, so a client can't look itself up first. It generates its key, sends `device_enroll`, and acts on the
answer. It SHOULD do this each time it opens: the same step makes an account's first device, repairs
an enrolment that failed, and costs one round trip otherwise.

## 7. What gets signed

Every signature here has a tag of its own, so one can't be presented as another. An address is
lowercased before signing.

| Signature | Bytes |
|---|---|
| Answer to a challenge | `dmcn-device-challenge-v1\0` ‖ nonce |
| Approval | `dmcn-device-approve-v1\0` ‖ address ‖ new device key ‖ nonce ‖ `approved_at` (8 bytes, big-endian) |
| Retirement | `dmcn-device-retire-v1\0` ‖ address ‖ retired device key ‖ nonce |
| Send proof (§9) | `dmcn-device-send-v1\0` ‖ envelope hash |

The tag on a challenge answer matters most. A relay picks the nonce and a device signs what it is
handed, so without the tag a hostile relay could serve the bytes of an approval as a challenge.

## 8. Pairing

Pairing brings an account onto a new device with no file to move. The newcomer has no standing, so
it speaks through a throwaway identity, and it is the person holding both devices who decides.

1. **The newcomer prepares.** It generates its device key and a throwaway identity at
   `pair-<16 hex digits>@pairing.local`, with a self-signed record that names one relay hint and
   expires after 15 minutes. Relays accept a `pairing.local` record without a DAR or routing grant.
   It confers no standing on any real address.
2. **It asks.** It sends a message to the account, signed by the throwaway key, with the subject
   `[DMCN] Device pairing request` and a `CloneRequest` attachment of type
   `application/x-dmcn-clone-request`, then shows the confirmation code.
3. **The owner confirms.** A device on the account shows the request and asks the person to **type
   in** the code the newcomer shows. It MUST NOT approve without a matching code. Anyone can send
   a request, and the code is what ties this approval to the device in the person's hand.
4. **The approver enrols the newcomer**, using `device_ed25519_pub` from the request, and stops
   here if that fails. Keys are never sent to a device the relay won't admit.
5. **The approver sends the keys.** A message to the throwaway address, signed by the account key
   and sealed to the throwaway X25519 key, with the subject `[DMCN] Device pairing approval` and a
   `CloneResponse` attachment of type `application/x-dmcn-clone-response`.
6. **The newcomer adopts them.** It checks the message was signed by the account's key as the
   directory lists it, then takes the keys and discards the throwaway identity.

Clients keep both message types out of the mail folders, and SHOULD show a waiting request to the
owner on every device.

The **confirmation code** binds the account and the exact keys the response will be sealed to:

```
SHA-256( "dmcn-pair-sas-v1\0" ‖ account address ‖ throwaway Ed25519 key ‖ throwaway X25519 key )
```

Take the first 6 bytes as a big-endian integer, reduce it modulo 10^12, and write it as 12 decimal
digits in three groups of four, such as `0428-9173-5560`. The address is used exactly as the
newcomer entered it.

```proto
message CloneRequest {
  bytes ephemeral_ed25519_pub = 1;
  bytes ephemeral_x25519_pub = 2;
  bytes device_id = 3;           // 16 bytes, cosmetic
  string label = 4;              // the name shown to the approver
  int64 requested_at = 5;
  bytes device_ed25519_pub = 6;  // the newcomer's device key
}

message CloneResponse {
  string address = 1;
  bytes ed25519_public = 2;
  bytes ed25519_private = 3;     // 64 bytes; empty for a read-only pairing
  bytes x25519_public = 4;
  bytes x25519_private = 5;
  bytes device_id = 6;
  int64 created_at = 7;
}
```

A device that already holds the keys, from a backup for example, still needs step 4 and can ignore
step 5.

### Read-only pairing

A device can be paired to read and organise a mailbox and never to send from it. It receives the
account's X25519 key, which opens mail, and not the Ed25519 key, which signs it. With §3 that is
enough for every class A operation and for nothing in class B. This is the pairing for a device
the owner doesn't want speaking for them: a shared screen, or a program that reads mail on the
owner's behalf.

The six steps above stand, with these differences:

- **The request says so, in its type.** In step 2 the `CloneRequest` travels as an attachment of
  type `application/x-dmcn-clone-request-read`. The message is the same in every other respect.
  The separate type is the safeguard: an approver that doesn't know it finds no pairing request in
  the message, so it can't answer with the full set of keys by mistake.
- **The approver tells the person which kind it is** in step 3, before the code is typed, in
  words about what the device will be able to do ("can read and organise mail, cannot send"),
  never in key names. The code is computed as for any pairing.
- **The response leaves the signing key out.** In step 5 `ed25519_private` is empty. Every other
  field is filled as usual.
- **The newcomer refuses a signing key it didn't ask for.** In step 6 a newcomer that asked to be
  read-only and receives a non-empty `ed25519_private` MUST discard the whole response without
  storing any of it, and report the pairing as failed.

An approver MUST NOT answer a read-only request with the signing key. It MAY answer an ordinary
request without one, where the person approving chooses to: a newcomer that asked for both and
receives an empty `ed25519_private` is read-only, and says so.

Enrolment in step 4 is unchanged, and the registry records nothing about which kind a device is.
What a read-only device can do follows from the key it lacks, not from a mark the relay keeps. A
client that wants to show the difference in the owner's device list puts it in the sealed label.

What follows from that, and what a client should tell the owner:

- **A read-only device can't approve, retire or veto.** Each of those is class B. It can't enrol
  the next device, remove a lost one, or stop a recovery request (§4).
- **It doesn't count as a way back in.** The relay's guard against retiring the last active device
  (§5) can't tell kinds apart, so it will let an owner retire every device that holds the signing
  key and keep a read-only one. An owner in that position has the recovery delay or nothing. A
  client SHOULD refuse to retire the last device it knows to hold the signing key.
- **It holds the key to all the mail.** Retiring it ends its access to the relay. It doesn't take
  the key back: that needs a rotation (`SPEC_EXT_ROTATION.md`).
- **It can't make a backup that restores an account.** It has no signing key to put in one.

## 9. Sending

A service that takes a client's message and sends it on for them MAY require a send proof: the
device's signature over the tagged envelope hash (§7), carried with the send and checked against
the sender's registry, under the same rules as §3. Once an account has devices, that keeps a removed
device from sending through that service.

**This does not stop a stolen account key from sending.** A STORE goes to the recipient's relay,
which holds no registry for the sender and carries no device proof. Anyone holding the account key
can sign a STORE and deliver it. Removing a device ends its access to the mailbox. To end the key's
power to send, rotate it. An implementation must not claim otherwise.

The reverse does hold. A device that has no account signing key can't send at all, whatever class A
lets it do: a STORE needs the sender's signature, and so does the header every recipient checks.

## 10. Several relays

A deployment with one node per domain can skip this section. Where an address has several relays
(`SPEC_EXT_FLEET.md`), each gates the mailbox on its own registry, so every change has to reach all
of them, or a device removed on one relay stays active on another. How it gets there is up to the
operator's fleet tooling.

Two rules bind it. A relay MUST NOT let replication turn a claimed registry back into one that
has never held a device: a retirement that arrives from a peer leaves a tombstone, like any other.
And a replicated record SHOULD carry its own evidence, so that a relay need not take a peer's word
for an active device it has never seen: the approver's key, signature and `approved_at`, or for a
recovery an `eligible_at` no earlier than this relay can justify from the DAR. A retirement of a
known device is accepted from a peer.

## 11. Finding out and rolling out

A relay with a registry advertises `device-registry` in `PingResponse.capabilities`, only once it
enforces §3. The capability says the relay keeps a registry. Only an enrolment attempt says where
this device stands (§6).

A relay that applies the two classes of §3 also advertises `device-reads`, and with it
`kv-write-time` (`SPEC_EXT_STORAGE.md` §4), which the first depends on. A client leaves the
account signature off a class A operation only where every relay it uses for that mailbox
advertises `device-reads`, and sends both signatures anywhere else. A relay without the token
refuses a request that has no account signature, so a client that guesses wrong is locked out, not
let in.

**Order matters.** The gate starts at a mailbox's first enrolment, and from then on every client
without a device is locked out. An operator adding a registry to a running deployment ships pairing
in the same release, after every client they care about can send a device proof. Otherwise the
first client to open claims the mailbox, and the owner's other devices have only the recovery delay
left.

## 12. Test vectors

An implementation checks against these before talking to a relay. Bytes are hex. The inputs:
address `Vector@Parity.Example` (mixed case, so the lowercasing is exercised), the device being
approved or retired is 32 bytes of `0x21`, the nonce and the envelope hash are 32 bytes of `0x22`,
and `approved_at` is `1700000000`.

| Signature | Signed bytes |
|---|---|
| Answer to a challenge | `646d636e2d6465766963652d6368616c6c656e67652d763100` ‖ 32 × `22` |
| Approval | `646d636e2d6465766963652d617070726f76652d763100` ‖ `766563746f72407061726974792e6578616d706c65` ‖ 32 × `21` ‖ 32 × `22` ‖ `000000006553f100` |
| Retirement | `646d636e2d6465766963652d7265746972652d763100` ‖ `766563746f72407061726974792e6578616d706c65` ‖ 32 × `21` ‖ 32 × `22` |
| Send proof | `646d636e2d6465766963652d73656e642d763100` ‖ 32 × `22` |

A retirement carries no time. It is not a zero: the eight bytes are absent.

The confirmation code for account `vector@parity.example`, a throwaway Ed25519 key of 32 bytes of
`0x01` and a throwaway X25519 key of 32 bytes of `0x02`, is `2309-4949-8238`.
