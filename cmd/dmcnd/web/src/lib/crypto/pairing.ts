// Device pairing (SPEC_EXT_DEVICES.md §8): the browser's half of internal/core/pairing.
//
// The new device mints a throwaway identity, publishes its self-signed record, sends a request
// into the account's mailbox, and adopts the keys from the account-signed answer. The device
// that approves seals the account's keys to the throwaway key.

import type { IdentityKeyPair } from './keys';
import { toHex } from './keys';
import { sign } from './sign';
import { ID_SELF_CTX } from './identity';
import { encodeIdentityRecord, encodeIdentitySignableBytes } from './protobuf';
import { encodeCloneRequest, decodeCloneRequest, encodeCloneResponse, decodeCloneResponse } from './protobuf';
import type { AttachmentInput } from './split';
import type { DecryptedAttachment } from './split';
import { bufferSource } from './bytes';

export const CLONE_REQUEST_CONTENT_TYPE = 'application/x-dmcn-clone-request';
// A request to read and organise the mailbox and never to send from it. A type of its own, so an
// approver that predates it finds no pairing request in the message and cannot answer with the
// signing key by mistake. Nothing here sends or answers one yet: it is listed so such a request
// is never shown as an attachment.
export const CLONE_REQUEST_READ_CONTENT_TYPE = 'application/x-dmcn-clone-request-read';
export const CLONE_RESPONSE_CONTENT_TYPE = 'application/x-dmcn-clone-response';
export const SUBJECT_REQUEST = '[DMCN] Device pairing request';
export const SUBJECT_APPROVAL = '[DMCN] Device pairing approval';
export const EPHEMERAL_DOMAIN = 'pairing.local';
export const EPHEMERAL_TTL_SECONDS = 15 * 60;

function ctxBytes(tag: string): Uint8Array {
  const t = new TextEncoder().encode(tag);
  const out = new Uint8Array(t.length + 1); // trailing NUL
  out.set(t, 0);
  return out;
}
const SAS_CTX = ctxBytes('dmcn-pair-sas-v1');

function concatAll(parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bufferSource(data)));
}

// confirmationCode mirrors pairing.ConfirmationCode in Go: SHA-256 over
// (ctx || account || ephEd || ephX), first 6 bytes → 12 decimal digits in groups.
export async function confirmationCode(
  accountAddress: string,
  ephEd25519Pub: Uint8Array,
  ephX25519Pub: Uint8Array
): Promise<string> {
  const buf = concatAll([SAS_CTX, new TextEncoder().encode(accountAddress), ephEd25519Pub, ephX25519Pub]);
  const h = await sha256(buf);
  let n = 0;
  for (let i = 0; i < 6; i++) n = n * 256 + h[i]; // < 2^48, safe in a JS number
  n = n % 1_000_000_000_000;
  const s = String(n).padStart(12, '0');
  return `${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}`;
}

// splitConfirmationCode cuts the code where the two devices stop agreeing to show
// the same thing: the approving device displays `shown` and makes the person TYPE
// `typed`, read off the new device's screen. A code that is merely displayed on
// both sides can be approved without ever looking at the other one — which is the
// whole attack the SAS exists to stop.
export function splitConfirmationCode(code: string): { shown: string; typed: string } {
  const groups = code.split('-');
  return { shown: groups.slice(0, -1).join('-'), typed: groups[groups.length - 1] ?? '' };
}

export function ephemeralAddress(): string {
  const b = crypto.getRandomValues(new Uint8Array(8));
  return `pair-${toHex(b)}@${EPHEMERAL_DOMAIN}`;
}

// buildEphemeralRecord encodes a self-signed, tier-0 IdentityRecord (RelayHints =
// [relayHint], short expiry) ready to publish.
export async function buildEphemeralRecord(
  address: string,
  eph: IdentityKeyPair,
  relayHint: string,
  nowSeconds: number
): Promise<Uint8Array> {
  const base = {
    version: 1,
    address,
    ed25519PublicKey: eph.ed25519Public,
    x25519PublicKey: eph.x25519Public,
    createdAt: eph.createdAt,
    expiresAt: nowSeconds + EPHEMERAL_TTL_SECONDS,
    relayHints: [relayHint],
    verificationTier: 0,
    // A fresh record starts at revision 1 — Go's identity.NewIdentityRecord and the browser's own
    // registration path (enrollment.ts) both do; this builder used to leave it at 0, which the
    // parity vector (pairing.test.ts) caught as a byte-level divergence from dmcncli's ephemeral.
    revision: 1,
  };
  const signable = await encodeIdentitySignableBytes(base);
  const seed = eph.ed25519Private.slice(0, 32);
  const sig = await sign(seed, concatAll([ID_SELF_CTX, signable]));
  return encodeIdentityRecord({ ...base, selfSignature: sig });
}

async function attachmentFor(contentType: string, filename: string, content: Uint8Array): Promise<AttachmentInput> {
  return {
    attachmentId: crypto.getRandomValues(new Uint8Array(16)),
    filename,
    contentType,
    sizeBytes: content.length,
    contentHash: await sha256(content),
    content,
  };
}

// cloneRequestAttachment builds the attachment carrying the new device's ephemeral public keys,
// and its own device key for the approver to enrol.
export async function cloneRequestAttachment(eph: IdentityKeyPair, label: string, nowSeconds: number, devicePub?: Uint8Array): Promise<AttachmentInput> {
  const body = await encodeCloneRequest({
    ephemeralEd25519Pub: eph.ed25519Public,
    ephemeralX25519Pub: eph.x25519Public,
    deviceId: eph.deviceId,
    label,
    requestedAt: nowSeconds,
    // The new device's own long-lived key, so the approver can enrol it while it is approving.
    // Only the public half travels; the private one is non-extractable and stays where it was
    // made, which is what a stolen account key cannot reproduce.
    deviceEd25519Pub: devicePub,
  });
  return attachmentFor(CLONE_REQUEST_CONTENT_TYPE, 'clone-request.bin', body);
}

// cloneResponseAttachment builds the attachment carrying the account key bundle.
export async function cloneResponseAttachment(account: IdentityKeyPair, accountAddress: string): Promise<AttachmentInput> {
  const body = await encodeCloneResponse({
    address: accountAddress,
    ed25519Public: account.ed25519Public,
    ed25519Private: account.ed25519Private,
    x25519Public: account.x25519Public,
    x25519Private: account.x25519Private,
    deviceId: account.deviceId,
    createdAt: account.createdAt,
  });
  return attachmentFor(CLONE_RESPONSE_CONTENT_TYPE, 'clone-response.bin', body);
}

export interface CloneRequestData {
  ephemeralEd25519Pub: Uint8Array;
  ephemeralX25519Pub: Uint8Array;
  deviceId: Uint8Array;
  label: string;
  requestedAt: number;
  /** The new device's long-lived signing key, empty from a client predating the registry. */
  deviceEd25519Pub: Uint8Array;
}

export async function extractCloneRequest(attachments: DecryptedAttachment[]): Promise<CloneRequestData | null> {
  const a = attachments.find(x => x.contentType === CLONE_REQUEST_CONTENT_TYPE);
  if (!a) return null;
  const d = await decodeCloneRequest(a.content);
  return {
    ephemeralEd25519Pub: new Uint8Array(d.ephemeralEd25519Pub),
    ephemeralX25519Pub: new Uint8Array(d.ephemeralX25519Pub),
    deviceId: new Uint8Array(d.deviceId),
    label: d.label,
    requestedAt: Number(d.requestedAt),
    deviceEd25519Pub: new Uint8Array(d.deviceEd25519Pub ?? []),
  };
}

export async function extractCloneResponse(attachments: DecryptedAttachment[]): Promise<IdentityKeyPair | null> {
  const a = attachments.find(x => x.contentType === CLONE_RESPONSE_CONTENT_TYPE);
  if (!a) return null;
  const d = await decodeCloneResponse(a.content);
  return {
    ed25519Public: new Uint8Array(d.ed25519Public),
    ed25519Private: new Uint8Array(d.ed25519Private),
    x25519Public: new Uint8Array(d.x25519Public),
    x25519Private: new Uint8Array(d.x25519Private),
    deviceId: new Uint8Array(d.deviceId),
    createdAt: Number(d.createdAt),
  };
}

// cloneResponseAddress decodes just the account address from a response attachment.
export async function cloneResponseAddress(attachments: DecryptedAttachment[]): Promise<string | null> {
  const a = attachments.find(x => x.contentType === CLONE_RESPONSE_CONTENT_TYPE);
  if (!a) return null;
  const d = await decodeCloneResponse(a.content);
  return d.address;
}
