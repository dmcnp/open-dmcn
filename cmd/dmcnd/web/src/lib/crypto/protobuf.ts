// Protobuf encode/decode backed by a statically generated module (pbjs
// static-module: web/app/proto/dmcn.js, reached via the @proto alias) instead of runtime
// reflection/codegen,
// so it works under a strict CSP with no 'unsafe-eval'. The static codecs are
// byte-identical to Go's deterministic marshaling (verified). The getRoot()/
// lookupType() shim keeps the existing helper call sites below unchanged.
import { dmcn } from '@proto';

interface StaticType {
  create(props: unknown): unknown;
  encode(msg: unknown): { finish(): Uint8Array };
  decode(data: Uint8Array): unknown;
}

const staticRoot = {
  lookupType(name: string): StaticType {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let cur: any = { dmcn };
    for (const part of name.split('.')) cur = cur?.[part];
    if (!cur) throw new Error('unknown proto type: ' + name);
    return cur as StaticType;
  },
};

async function getRoot(): Promise<typeof staticRoot> {
  return staticRoot;
}

// decodeAs is the one place the untyped reflection decode meets the declared shapes below. The
// generated codec returns an untyped message; the shape each decode* function declares is the
// contract Go's canonical encoding guarantees, so the cast lives here, once, instead of an
// `as any` at every call site.
function decodeAs<T>(type: StaticType, data: Uint8Array): T {
  return type.decode(data) as T;
}

// RotationEntryWire mirrors dmcn.identity.RotationEntry — one owner-authorized transition from
// one account keypair to the next. It carries TWO signatures because one proves only half of a
// handover: `signature` is the outgoing key's consent to give the address up, `nextSignature` is
// the incoming key's acceptance of it. Both travel with the entry because entries are read
// DETACHED — from an AddressHistoryRecord and over the directory API — where the record's own
// self-signature is unavailable to close the gap.
export interface RotationEntryWire {
  version: number;
  address: string;
  retiredEd25519PublicKey: Uint8Array;
  retiredX25519PublicKey: Uint8Array;
  nextEd25519PublicKey: Uint8Array;
  nextX25519PublicKey: Uint8Array;
  rotatedAt: number;
  nextRevision: number;
  /** SHA-256 of the previous entry's `signature`; absent at the address's first rotation. */
  prevSignatureHash?: Uint8Array;
  /** The key that produced `signature`: the retiring key, or the owner's recovery key. */
  authorizingEd25519PublicKey: Uint8Array;
  /** Leaf Credential (role "device") of the enrolled device that authorized this rotation. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  deviceCredential?: any;
  /** By deviceCredential.subject over the transition — what a stolen ACCOUNT key cannot produce. */
  deviceSignature?: Uint8Array;
  signature?: Uint8Array;
  nextSignature?: Uint8Array;
}

// Encode an address's complete rotation history. It carries no signature of its own: every entry
// is already signed by the keys it names, so integrity comes from the entries.
export async function encodeAddressHistory(h: {
  version: number;
  domain: string;
  address: string;
  chain: RotationEntryWire[];
}): Promise<Uint8Array> {
  const root = await getRoot();
  const T = root.lookupType('dmcn.identity.AddressHistoryRecord');
  return T.encode(T.create(canonical(h))).finish();
}

// decodeAddressHistory parses a marshaled AddressHistoryRecord. Its entries are handed on as they
// arrived: a chain that is re-published has to re-encode to the bytes each entry's signatures
// cover, so nothing here rebuilds them.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function decodeAddressHistory(data: Uint8Array): Promise<any> {
  const root = await getRoot();
  return root.lookupType('dmcn.identity.AddressHistoryRecord').decode(data);
}

// decodeAddressRemoval parses a marshaled AddressRemovalRecord — an address's tombstones, which a
// new one must EXTEND rather than replace.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function decodeAddressRemoval(data: Uint8Array): Promise<any> {
  const root = await getRoot();
  return root.lookupType('dmcn.identity.AddressRemovalRecord').decode(data);
}

// decodeCredential parses a marshaled dmcn.identity.Credential so it can be NESTED inside another
// message. This client treats credentials as opaque bytes everywhere else — it verifies none of
// them — and the one place that changes is a rotation entry, which carries the device's credential
// inside its own protobuf and so has to hold it as a message rather than a blob.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function decodeCredential(data: Uint8Array): Promise<any> {
  const root = await getRoot();
  return root.lookupType('dmcn.identity.Credential').decode(data);
}

// Encode a rotation entry with NO signature over it yet — what the enrolled device signs under
// ROTATION_DEVICE_CTX to bind itself to this handover. Must match Go's RotationEntry.deviceBytes().
export async function encodeRotationDeviceBytes(entry: RotationEntryWire): Promise<Uint8Array> {
  const root = await getRoot();
  const RotationEntry = root.lookupType('dmcn.identity.RotationEntry');
  const msg = RotationEntry.create(canonical({
    ...entry, deviceSignature: undefined, signature: undefined, nextSignature: undefined,
  }));
  return RotationEntry.encode(msg).finish();
}

// Encode a rotation entry WITHOUT either account signature — the bytes the retiring (or recovery)
// key signs under ROTATION_CTX. It COVERS the device attestation, so an outgoing key cannot
// consent and have a different device swapped in afterwards. Matches Go's consentBytes().
export async function encodeRotationConsentBytes(entry: RotationEntryWire): Promise<Uint8Array> {
  const root = await getRoot();
  const RotationEntry = root.lookupType('dmcn.identity.RotationEntry');
  const msg = RotationEntry.create(canonical({ ...entry, signature: undefined, nextSignature: undefined }));
  return RotationEntry.encode(msg).finish();
}

// Encode a rotation entry WITHOUT the acceptance signature — the bytes the incoming key signs
// under ROTATION_ACCEPT_CTX. It covers `signature`, so the incoming key countersigns the exact
// handover the outgoing key offered rather than a handover it could still be swapped for. Must
// match Go's RotationEntry.acceptBytes().
export async function encodeRotationAcceptBytes(entry: RotationEntryWire): Promise<Uint8Array> {
  const root = await getRoot();
  const RotationEntry = root.lookupType('dmcn.identity.RotationEntry');
  const msg = RotationEntry.create(canonical({ ...entry, nextSignature: undefined }));
  return RotationEntry.encode(msg).finish();
}

export async function encodeIdentityRecord(record: {
  version: number;
  address: string;
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  createdAt: number;
  expiresAt: number;
  relayHints: string[];
  verificationTier: number;
  requireOnion?: boolean;
  // Owner-signed monotonic version. Go's NewIdentityRecord starts at 1; the browser omitted it
  // entirely (encoding 0), which made "monotonic" false across the two producers — a Go-built
  // record beat any browser-built one on acceptIdentity's anti-rollback comparison, and a
  // browser record could never displace it. Not a security control either way: the owner signs
  // it, so a hostile rebind just picks its own value.
  revision?: number;
  // The address's own key-change history and the recovery key that may authorize the next
  // transition. Both are OWNER-signed, so they belong in the signable bytes below as well.
  rotationChain?: RotationEntryWire[];
  recoveryEd25519PublicKey?: Uint8Array;
  selfSignature?: Uint8Array;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  // canonical() strips JS default-valued fields (e.g. verificationTier=0) so the
  // bytes match Go's proto3 deterministic marshal
  // — required for a tier-0 ephemeral record's self-signature to verify.
  const msg = IdentityRecord.create(canonical(record));
  return IdentityRecord.encode(msg).finish();
}

// decodeIdentityRecord decodes an IdentityRecord (all fields), e.g. the requester's
// self-signed record carried in a countersign request.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function decodeIdentityRecord(data: Uint8Array): Promise<any> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  return IdentityRecord.decode(data);
}

// Encode identity record WITHOUT selfSignature (for signing)
export async function encodeIdentitySignableBytes(record: {
  version: number;
  address: string;
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  createdAt: number;
  expiresAt: number;
  relayHints: string[];
  verificationTier: number;
  requireOnion?: boolean;
  revision?: number;
  // Covered by the owner self-signature, so a record carrying a rotation chain verifies only
  // when these are encoded too. A client that omitted them would reject every rotated record on
  // the network — which is why the reader ships before any producer does.
  rotationChain?: RotationEntryWire[];
  recoveryEd25519PublicKey?: Uint8Array;
  // Anything else a record carries is ignored here, deliberately — see below.
  [other: string]: unknown;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  const msg = IdentityRecord.create(canonical(pickOwn(record, IDENTITY_SIGNED_FIELDS)));
  return IdentityRecord.encode(msg).finish();
}

/**
 * The fields the OWNER signs, mirroring Go's IdentityRecord.signableBytes() exactly.
 *
 * Everything else a record carries is operator-owned and outside the self-signature:
 * `relay_hints` (it rides in the routing credential), the address and routing credentials
 * themselves, the attestations and operator credentials — and `self_signature`, which is what is
 * being signed.
 */
const IDENTITY_SIGNED_FIELDS = [
  'version', 'address', 'ed25519PublicKey', 'x25519PublicKey', 'createdAt', 'expiresAt',
  'verificationTier', 'requireOnion', 'revision', 'rotationChain', 'recoveryEd25519PublicKey',
] as const;

/**
 * Copy the named fields that the source ACTUALLY HAS, and no others.
 *
 * Both halves are load-bearing, and each was a bug on its own. Spreading the whole record picked
 * up the operator-owned fields a record decoded off the wire carries, producing signable bytes no
 * signature could ever cover — a verifier written that way rejects every real record while passing
 * every fixture built in this file. Naming the fields but reading them unconditionally is the
 * mirror image: protobufjs serves absent scalars from the message PROTOTYPE, so `expiresAt` comes
 * back as a zero Long rather than undefined, canonical() does not recognise that as a default, and
 * a field the sender never encoded gets encoded here.
 *
 * Own-properties-only is what makes the result match the bytes that were on the wire, and naming
 * the fields is what keeps a new signed field a deliberate addition rather than an accident.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function pickOwn(src: any, fields: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    if (Object.prototype.hasOwnProperty.call(src, f)) out[f] = src[f];
  }
  return out;
}

// AttachmentWire mirrors dmcnpb.AttachmentRecord (message.proto). Each record is
// canonicalized so a zero-valued inner field (e.g. a 0-byte attachment's
// size_bytes/content) is stripped to match Go's deterministic marshal — see canonical().
export interface AttachmentWire {
  attachmentId: Uint8Array;
  filename: string;
  contentType: string;
  sizeBytes: number;
  contentHash: Uint8Array;
  content: Uint8Array;
  /** Bare MIME Content-ID (no <>) for an inline part referenced by <img src="cid:…">. */
  contentId?: string;
  /** 'inline' or 'attachment'; omitted = attachment. */
  disposition?: string;
}

// BodyWire mirrors dmcnpb.MessageBody. `body` is always the text/plain primary; richer
// renderings (text/html) ride in `alternatives` — the multipart/alternative analog.
export interface BodyWire {
  contentType: string;
  content: Uint8Array;
}

// --- Split header/body ---
//
// The only shape this client produces. The older whole-message form (PlaintextMessage /
// SignedMessage sealed into one blob) had one caller left — outbound-to-legacy mail sealed
// for the bridge — and that moved onto the split form too, because the shared To/Cc audience
// a bridge needs for Reply All exists only on a split header. Its codecs are gone with it;
// Go still reads and writes v1 for records predating the split.

export interface MessageHeaderFields {
  version: number;
  messageId: Uint8Array;
  threadId: Uint8Array;
  senderAddress: string;
  senderPublicKey: Uint8Array;
  recipientAddress: string;
  sentAt: number;
  subject: string;
  attachmentCount: number;
  bodySize: number;
  snippet: string;
  replyToId?: Uint8Array;
  bodyHash: Uint8Array;
  // CIDv1(raw/sha2-256) of the body ciphertext blob. Signed (covered by the header
  // signature). Absent/empty for pre-feature headers; canonical() strips it then.
  bodyContentAddress?: Uint8Array;
  // Full recipient lists, signed and visible to every recipient of this envelope.
  // to/cc are identical across all copies; bcc is only set on the sender's own Sent
  // self-copy (recipient copies pass [] or omit it, which canonical() strips — so a
  // Bcc recipient is never revealed, matching Go's empty-repeated omission).
  to?: string[];
  cc?: string[];
  bcc?: string[];
  // Optional human-readable sender name (legacy mail's From display name), signed with
  // the rest of the header. Display only — never an identity; see trust/displayName.ts.
  // Empty/absent is stripped by canonical(), matching Go's omission of an empty string,
  // so a header that predates the field re-encodes byte-identically on the verify path.
  senderDisplay?: string;
}

// encodeMessageHeader is the canonical serialization signed by the sender.
// canonical strips JS default-valued fields so protobufjs (which serializes every
// property that is set) emits exactly what Go's proto3 marshaling does — Go skips
// zero numbers, empty strings, empty bytes, and empty repeateds. It recurses into
// plain objects (e.g. a nested MessageBody) but leaves Uint8Array/arrays intact.
// Fixed-size zero BYTE fields that Go always writes (e.g. reply_to_id = 16 zero
// bytes) are non-empty Uint8Arrays, so they survive — callers add them explicitly.
// An address-removal record: the tombstone that retires a binding. `removedBindings` carries the
// keys being retired with the time each was. Signed over the context-prefixed signable bytes
// (crypto/identity.ts removalSigningBytes) — with self_signature cleared, exactly as Go's
// AddressRemovalRecord.signableBytes() does.
export interface RemovalRecordFields {
  version: number;
  domain: string;
  address: string;
  removedBindings: { ed25519PublicKey: Uint8Array; removedAt: number }[];
  revision: number;
  createdAt: number;
}

export async function encodeRemovalSignableBytes(rm: RemovalRecordFields): Promise<Uint8Array> {
  const root = await getRoot();
  const AddressRemovalRecord = root.lookupType('dmcn.identity.AddressRemovalRecord');
  const msg = AddressRemovalRecord.create(canonical({ ...rm, selfSignature: undefined }));
  return AddressRemovalRecord.encode(msg).finish();
}

export async function encodeRemovalRecord(rm: RemovalRecordFields & { selfSignature: Uint8Array }): Promise<Uint8Array> {
  const root = await getRoot();
  const AddressRemovalRecord = root.lookupType('dmcn.identity.AddressRemovalRecord');
  return AddressRemovalRecord.encode(AddressRemovalRecord.create(canonical(rm))).finish();
}

/**
 * A decoded protobufjs message, or the Long it hands back for a 64-bit field.
 *
 * Both are passed through VERBATIM below. A decoded message's own properties are exactly the
 * fields that were on the wire, so re-encoding it reproduces the bytes its signature covers —
 * where rebuilding it as a plain object would drop a zero the sender actually encoded, and would
 * flatten a Long into {low, high}, which the writer reads back as a different number.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function decoded(v: any): boolean {
  if (!v || typeof v !== 'object') return false;
  if (typeof v.$type?.encode === 'function') return true; // a message
  // A 64-bit field, as either long.js or protobufjs's own fallback hands it back.
  return typeof v.low === 'number' && typeof v.high === 'number';
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function canonical(value: any): any {
  if (value instanceof Uint8Array) return value;
  if (decoded(value)) return value;
  // Recurse into array ELEMENTS (e.g. attachment records) so a zero-valued field
  // inside one is stripped too — Go skips it, protobufjs would otherwise emit it,
  // and the resulting MessageContent bytes (hence body_hash) would diverge.
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const out: any = {};
    for (const [k, v] of Object.entries(value)) {
      if (v === undefined || v === null) continue;
      if (typeof v === 'number' && v === 0) continue;
      if (typeof v === 'string' && v === '') continue;
      if (typeof v === 'boolean' && v === false) continue;
      if (v instanceof Uint8Array && v.length === 0) continue;
      if (Array.isArray(v) && v.length === 0) continue;
      out[k] = canonical(v);
    }
    return out;
  }
  return value;
}

export async function encodeMessageHeader(h: MessageHeaderFields): Promise<Uint8Array> {
  const root = await getRoot();
  const MessageHeader = root.lookupType('dmcn.message.MessageHeader');
  // Match Go's MessageHeader.toProto(): always emit reply_to_id (16 zero bytes when
  // not a reply); strip default scalars/strings. This is the signed-over form, so
  // it must equal what the Go recipient re-encodes to verify the signature.
  //
  // NOTE: protobufjs decode yields an EMPTY Uint8Array (not undefined) for an
  // absent reply_to_id, so `?? ` wouldn't catch it and canonical() would then
  // strip the empty field — dropping reply_to_id on the verify-side re-encode and
  // breaking every signature check. Check the length: only a real 16-byte reply id
  // is kept; anything else (absent/empty) becomes 16 zero bytes.
  const replyToId = h.replyToId && h.replyToId.length === 16 ? h.replyToId : new Uint8Array(16);
  const obj = canonical({ ...h, replyToId });
  return MessageHeader.encode(MessageHeader.create(obj)).finish();
}

export async function encodeSignedHeader(sh: {
  header: MessageHeaderFields;
  senderSignature: Uint8Array;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const SignedHeader = root.lookupType('dmcn.message.SignedHeader');
  return SignedHeader.encode(SignedHeader.create(sh)).finish();
}

export async function decodeSignedHeader(data: Uint8Array): Promise<{
  header: MessageHeaderFields;
  senderSignature: Uint8Array;
}> {
  const root = await getRoot();
  const SignedHeader = root.lookupType('dmcn.message.SignedHeader');
  return decodeAs(SignedHeader, data);
}

export async function encodeMessageContent(c: {
  body: BodyWire;
  attachments?: AttachmentWire[];
  alternatives?: BodyWire[];
}): Promise<Uint8Array> {
  const root = await getRoot();
  const MessageContent = root.lookupType('dmcn.message.MessageContent');
  // body_hash is computed over these bytes and verified by Go against its own
  // canonical encoding, so strip default scalars/strings (e.g. an empty body).
  return MessageContent.encode(MessageContent.create(canonical(c))).finish();
}

export async function decodeMessageContent(data: Uint8Array): Promise<{
  body: { contentType: string; content: Uint8Array };
  // Richer renderings of body (e.g. text/html) — multipart/alternative analog.
  alternatives?: Array<{ contentType: string; content: Uint8Array }>;
  attachments: Array<{ filename: string; contentType: string; content: Uint8Array; contentId?: string; disposition?: string }>;
}> {
  const root = await getRoot();
  const MessageContent = root.lookupType('dmcn.message.MessageContent');
  return decodeAs(MessageContent, data);
}

export async function encodeSplitEnvelope(env: {
  version: number;
  messageId: Uint8Array;
  createdAt: number;
  recipients: Array<{
    deviceId: Uint8Array;
    recipientXPub: Uint8Array;
    ephemeralXPub: Uint8Array;
    wrappedCek: Uint8Array;
    cekNonce: Uint8Array;
    cekTag: Uint8Array;
    kdf?: number;
  }>;
  encryptedHeader: Uint8Array;
  headerNonce: Uint8Array;
  headerTag: Uint8Array;
  headerSizeClass: number;
  encryptedBody: Uint8Array;
  bodyNonce: Uint8Array;
  bodyTag: Uint8Array;
  bodySizeClass: number;
  bodyContentAddress: Uint8Array; // cleartext CIDv1 of the body blob (field 18)
}): Promise<Uint8Array> {
  const root = await getRoot();
  const EncryptedEnvelope = root.lookupType('dmcn.message.EncryptedEnvelope');
  // Emit the same canonical fixed-size zero fields Go's EncryptedEnvelope.ToProto()
  // always writes (payload_nonce[12], payload_tag[16], ratchet_pub_key[32]). They
  // are all-zero for a split envelope but non-empty on the wire, so omitting them
  // would make our bytes — and thus the STORE signature hash — differ from what the
  // relay re-marshals and verifies. See internal/core/message/encrypt.go ToProto().
  const canonical = {
    ...env,
    payloadNonce: new Uint8Array(12),
    payloadTag: new Uint8Array(16),
    ratchetPubKey: new Uint8Array(32),
  };
  return EncryptedEnvelope.encode(EncryptedEnvelope.create(canonical)).finish();
}

export async function decodeMailboxEntry(data: Uint8Array): Promise<{
  hash: Uint8Array;
  storedAt: number;
  bodySize: number;
  recipients: Array<{
    deviceId: Uint8Array;
    recipientXPub: Uint8Array;
    ephemeralXPub: Uint8Array;
    wrappedCek: Uint8Array;
    cekNonce: Uint8Array;
    cekTag: Uint8Array;
    kdf?: number;
  }>;
  encryptedHeader: Uint8Array;
  headerNonce: Uint8Array;
  headerTag: Uint8Array;
  headerSizeClass: number;
}> {
  const root = await getRoot();
  const MailboxEntry = root.lookupType('dmcn.relay.MailboxEntry');
  return decodeAs(MailboxEntry, data);
}

export async function decodeMailboxBody(data: Uint8Array): Promise<{
  encryptedBody: Uint8Array;
  bodyNonce: Uint8Array;
  bodyTag: Uint8Array;
  bodySizeClass: number;
}> {
  const root = await getRoot();
  const MailboxBody = root.lookupType('dmcn.relay.MailboxBody');
  return decodeAs(MailboxBody, data);
}
