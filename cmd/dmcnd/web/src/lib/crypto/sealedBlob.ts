// sealedBlob mirrors Go's internal/core/message.SealedBlob: arbitrary plaintext
// encrypted under a random CEK (AES-256-GCM) with the CEK wrapped to one or more
// X25519 recipients (same KEM as the message envelope). It is the browser side of
// the recipient mail-filter list — sealed to BOTH the owner's key and the mailbox
// relay's key, so the mailbox can enforce it while the owner edits it anywhere.
//
// Wire shape MUST match Go's encoding/json of SealedBlob: snake_case keys with
// base64-string values for every []byte field.

import { wrapCEK, aesGcmEncrypt } from './encrypt';
import { unwrapCEK, aesGcmDecrypt } from './decrypt';
import { toBase64, fromBase64 } from './keys';

interface SealedRecipientJSON {
  recipient_xpub: string;
  ephemeral_xpub: string;
  wrapped_cek: string;
  cek_nonce: string;
  cek_tag: string;
  // Derivation generation, same meaning as RecipientRecord.kdf: omitted means 1. A sealed blob
  // has no envelope and no version of its own, so the wrap carries it here.
  kdf?: number;
}

export interface SealedBlobJSON {
  nonce: string;
  ciphertext: string;
  tag: string;
  recipients: SealedRecipientJSON[];
}

const DEVICE_ID_ZERO = new Uint8Array(16);

// sealToRecipients encrypts plaintext under a fresh CEK and wraps that CEK to each
// recipient X25519 public key, returning the Go-compatible JSON object.
export async function sealToRecipients(
  plaintext: Uint8Array,
  recipientPubs: Uint8Array[]
): Promise<SealedBlobJSON> {
  if (recipientPubs.length === 0) throw new Error('seal: no recipients');
  const cek = crypto.getRandomValues(new Uint8Array(32));
  const { nonce, ciphertext, tag } = await aesGcmEncrypt(cek, plaintext);
  const recipients: SealedRecipientJSON[] = [];
  for (const pub of recipientPubs) {
    const r = await wrapCEK(cek, { deviceId: DEVICE_ID_ZERO, x25519Pub: pub });
    recipients.push({
      recipient_xpub: toBase64(r.recipientXPub),
      ephemeral_xpub: toBase64(r.ephemeralXPub),
      wrapped_cek: toBase64(r.wrappedCek),
      cek_nonce: toBase64(r.cekNonce),
      cek_tag: toBase64(r.cekTag),
      ...(r.kdf ? { kdf: r.kdf } : {}),
    });
  }
  return { nonce: toBase64(nonce), ciphertext: toBase64(ciphertext), tag: toBase64(tag), recipients };
}

// openSealed decrypts a SealedBlobJSON with the owner's non-extractable X25519
// derive handle (+ its public key to pick the matching recipient record).
export async function openSealed(
  blob: SealedBlobJSON,
  x25519Derive: CryptoKey,
  x25519Pub: Uint8Array
): Promise<Uint8Array> {
  const pubB64 = toBase64(x25519Pub);
  const ordered = [...blob.recipients].sort((a) =>
    a.recipient_xpub === pubB64 ? -1 : 1
  );
  let lastErr: unknown;
  for (const r of ordered) {
    try {
      const cek = await unwrapCEK(
        {
          recipientXPub: fromBase64(r.recipient_xpub),
          ephemeralXPub: fromBase64(r.ephemeral_xpub),
          wrappedCek: fromBase64(r.wrapped_cek),
          cekNonce: fromBase64(r.cek_nonce),
          cekTag: fromBase64(r.cek_tag),
          kdf: r.kdf,
        },
        x25519Derive,
        // The reader's OWN key, never r.recipient_xpub: this loop deliberately tries records
        // that are not ours, and the v2 derivation must not be bound to a value the sealer
        // chose. Matches Go's tryOpen.
        x25519Pub
      );
      return await aesGcmDecrypt(cek, fromBase64(blob.nonce), fromBase64(blob.ciphertext), fromBase64(blob.tag));
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error('openSealed: no recipient record opened with this key: ' + String(lastErr));
}
