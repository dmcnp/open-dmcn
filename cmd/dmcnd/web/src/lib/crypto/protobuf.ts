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

export async function encodeIdentityRecord(record: {
  version: number;
  address: string;
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  createdAt: number;
  expiresAt: number;
  relayHints: string[];
  verificationTier: number;
  bridgeCapability: boolean;
  requireOnion?: boolean;
  // Owner-signed monotonic version. Go's NewIdentityRecord starts at 1; the browser omitted it
  // entirely (encoding 0), which made "monotonic" false across the two producers — a Go-built
  // record beat any browser-built one on acceptIdentity's anti-rollback comparison, and a
  // browser record could never displace it. Not a security control either way: the owner signs
  // it, so a hostile rebind just picks its own value.
  revision?: number;
  selfSignature?: Uint8Array;
  // Domain countersignature (optional). Excluded from signableBytes, so adding it
  // does not invalidate the self-signature.
  domainCountersignature?: Uint8Array;
  domainCountersignedAt?: number;
  domainCountersignerPubkey?: Uint8Array;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  // canonical() strips JS default-valued fields (e.g. verificationTier=0,
  // bridgeCapability=false) so the bytes match Go's proto3 deterministic marshal
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

// encodeCountersignBinding is the exact byte sequence the domain authority signs
// when countersigning an address: an IdentityRecord with ONLY the minimal binding
// fields set. Must match Go's domainCountersignableBytes (identity.go).
export async function encodeCountersignBinding(b: {
  address: string;
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  domainCountersignedAt: number;
  domainCountersignerPubkey: Uint8Array;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  return IdentityRecord.encode(IdentityRecord.create(canonical(b))).finish();
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
  bridgeCapability: boolean;
  requireOnion?: boolean;
  revision?: number;
}): Promise<Uint8Array> {
  const root = await getRoot();
  const IdentityRecord = root.lookupType('dmcn.identity.IdentityRecord');
  const msg = IdentityRecord.create(canonical({
    ...record,
    // relay_hints is operator-owned (carried in the operator-signed routing credential),
    // so it is excluded from the owner self-signature. Must match Go's signableBytes().
    relayHints: undefined,
    selfSignature: undefined,
  }));
  return IdentityRecord.encode(msg).finish();
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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function canonical(value: any): any {
  if (value instanceof Uint8Array) return value;
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
  return SignedHeader.decode(data) as any;
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
  return MessageContent.decode(data) as any;
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
  }>;
  encryptedHeader: Uint8Array;
  headerNonce: Uint8Array;
  headerTag: Uint8Array;
  headerSizeClass: number;
}> {
  const root = await getRoot();
  const MailboxEntry = root.lookupType('dmcn.relay.MailboxEntry');
  return MailboxEntry.decode(data) as any;
}

export async function decodeMailboxBody(data: Uint8Array): Promise<{
  encryptedBody: Uint8Array;
  bodyNonce: Uint8Array;
  bodyTag: Uint8Array;
  bodySizeClass: number;
}> {
  const root = await getRoot();
  const MailboxBody = root.lookupType('dmcn.relay.MailboxBody');
  return MailboxBody.decode(data) as any;
}
