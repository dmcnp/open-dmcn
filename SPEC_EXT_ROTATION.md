# DMCNP extension: owner key rotation

**Status:** optional extension to [`SPEC_CORE.md`](SPEC_CORE.md). Off by default on every domain.

The core lets an address move to a new key in one way only: the domain root tombstones the old
key (`SPEC_CORE.md` §1). This extension adds a second way that needs no operator: the address
re-keys itself, and publishes a chain of signed transitions that proves each key handed the
address to the next. It also defines the `device` credential, which is what makes a stolen
account key insufficient to do that.

Who needs it: a domain that enables rotation, the nodes that serve that domain (they decide
whether a rotated record is admitted), and readers that want to follow a correspondent's key
change instead of treating it as a new, unverified key. A core reader that ignores this
extension still verifies the new record; it just has no evidence that the new key belongs to the
same person as the old one, and treats the change as it treats any key change.

## 1. What it costs

The rule this replaces required the root in every case, so that a stolen key stayed recoverable:
an attacker holding it could read mail, but could not take the address permanently. Rotation
gives that up for something users need more, which is the ability to re-key without an operator
and to keep an address when a device is lost. The price is that key compromise stops being
operator-recoverable and becomes a race. Domains that want the older property leave rotation
disabled, which is the default.

## 2. Turning it on

A domain enables rotation in its DAR. Every field below is covered by the DAR self-signature.
They are domain-level settings rather than per-node ones because nodes that disagreed about
which rotations are admissible would split record admission.

- **`policy_flags` bit 5, `ALLOW_KEY_ROTATION`.** Off unless set. Every DAR published before the
  bit existed leaves it unset, so rotation is never on unless the root has republished the DAR
  to turn it on.
- **`rotation_min_device_age_days`.** How long a device credential must have been enrolled
  before it can authorise a rotation. `0` means the protocol default, which is 30 days, so a
  domain that enables rotation and leaves this alone still gets a minimum. `0xFFFFFFFF` means no
  minimum, which a domain has to choose explicitly (a test fleet, or a domain whose devices are
  provisioned by an admin who already controls enrolment).
- **`device_recovery_delay_hours`.** How long an unapproved device must wait before it can act
  on a mailbox it joined through recovery, the path an owner takes when every device they had is
  gone. `0` means the deployment's default; `0xFFFFFFFF` (`DEVICE_RECOVERY_DISABLED`) removes
  the recovery path. Only a relay that keeps a device registry reads it (§3). The cost runs both
  ways. With a recovery path, a stolen account key can eventually take the mailbox, after the
  delay and if nobody vetoes. Without one, an owner who loses every device loses the mailbox,
  short of an operator ceremony.

## 3. Device credentials

A **`device`** credential (role `device`, issued under the `device` grant) marks one enrolled
device of an account. Its subject is a signing key generated on that device and held nowhere
else: not in the keystore bundle, not in a backup export, not in the payload that pairs a new
device. Possession of the account key alone therefore never yields one. Its `issued_at` fixes
when the device was enrolled, which lets any node weigh a device's tenure without holding
mailbox state.

Device credentials are used in two places:

- **Rotation** (§4): every transition carries an enrolled device's attestation.
- **Mailbox access.** `FetchProof` and `MailboxOp` carry an optional `device_ed25519_public_key`
  and `device_signature` over the same challenge nonce as the account signature (`SPEC_CORE.md`
  §5). A relay that keeps a device registry requires them once a mailbox has enrolled a device.
  The account key says whose mailbox it is, and the device key says the request comes from
  somewhere the owner approved. A key copied out of a backup can only answer the first. A
  mailbox with no enrolled device is answered on the account signature alone.

How devices are enrolled, approved and removed is not part of the open protocol.

## 4. The rotation chain and the history record

### Owner rotation (`RotationEntry`)

An address re-keys itself by publishing a record whose `rotation_chain` ends in a transition
from the key being displaced to the key taking over. Each entry carries three signatures, and a
verifier MUST check all of them: the outgoing key's consent, the incoming key's acceptance, and
an enrolled device's attestation. They nest: the device signs the transition, the consent covers
that attestation, and the acceptance covers the consent. Because of the nesting, no signature
can be lifted from one transition onto another.

An implementation MUST refuse a chain whose entries do not link (`retired` keys matching the
preceding `next` keys, `prev_signature_hash` matching the preceding signature), whose times or
revisions do not advance, or whose terminal entry names keys other than the ones the record
itself publishes. The last of these is what stops a genuine chain being carried by a record it
never belonged to.

**Device attestation and tenure.** The device credential names when that device was enrolled,
and a domain MAY require a minimum tenure before a device can authorise a rotation. This is the
substance of the trade above: a stolen account key alone attests nothing, because device keys
are generated on their device and never travel.

**Precedence.** A root-signed tombstone covering the incumbent key is evaluated first, and a
chain does not displace it. Otherwise an offboarded key could argue its way back. A key the root
has tombstoned MUST NOT be rotated *into*.

**Limits.** The chain proves continuity, not origin. It says each key handed the address to the
next, and nothing about whether the first key ever belonged to this person. Only someone who saw
the first binding made can vouch for that.

### The history record (`AddressHistoryRecord`)

The chain carried on an identity record is capped, because it is re-marshalled on every
republish. The complete history is served beside it, keyed on `SHA-256(address)` like the
removal record, and a reader whose pinned key falls outside the retained window resolves it
rather than giving up.

It carries no signature of its own and needs none: every entry is already signed by the keys it
names, so extending the history takes keys the extender holds. An implementation MUST refuse a
history that does not begin at the address's first rotation, and MUST refuse one that does not
strictly extend what it already holds. Histories only grow, so nothing already recorded can be
quietly rewritten. Truncation on the record is visible by design: the oldest retained entry
names a predecessor that is absent, which a reader tells apart from a genuine genesis.

Together, the chain and the history record make a key change evidence anyone can check, rather
than evidence only to whoever already held a pin. They do not establish that every reader was
shown the same history. Only cross-observer consistency (a gossiped log) can do that.

### The recovery key

An `IdentityRecord` may carry a `recovery_ed25519_public_key`: an owner-held key kept apart from
the active one, covered by the owner self-signature. It may sign the next transition's consent
in place of the key being retired, so losing the active key stops being terminal. A
`RotationEntry` names whichever key consented in `authorizing_ed25519_public_key`.

## 5. Signatures

A `RotationEntry` carries three signatures over three nested extents, each with its own tag:
`dmcn-identity-rotation-device-v1\0` over the transition alone, `dmcn-identity-rotation-v1\0`
over that plus the device attestation, and `dmcn-identity-rotation-accept-v1\0` over that plus
the consent. Separate tags are what stop an acceptance verifying as a consent. A key that merely
received an address must never appear to have handed it on. They follow the core signing
convention (`SPEC_CORE.md` §2).

## 6. Wire

- **`GetHistory{address}` → `GetHistoryResponse{found, record}`** on `/dmcn/relay/1.0.0`: a
  public read of the address's `AddressHistoryRecord`, verified through the signatures on its
  own entries.
- **Publication.** Nodes of a fleet replicate history records with `PutRecord`
  (`RECORD_KIND_HISTORY`, [`SPEC_EXT_FLEET.md`](SPEC_EXT_FLEET.md)), and admit one only if it
  strictly extends what they hold.
- **Capabilities.** A relay advertises two `PingResponse.capabilities` tokens. `rotation-schema`
  means it parses and re-marshals `rotation_chain` and `recovery_ed25519_public_key`, so a
  record carrying them verifies there instead of failing its self-signature. `rotation` means it
  enforces the rotation re-bind rule, so a record with a valid chain is admitted on a domain
  that opts in. A client about to re-key needs `rotation` on its fleet before it starts: a fleet
  that only parses the chain would still refuse the re-bind.

Because `rotation_chain` and `recovery_ed25519_public_key` are covered by the owner
self-signature, a reader whose code predates them rejects every record that carries them. Ship
readers first, then producers; `rotation-schema` is how a producer learns the readers have
landed.
