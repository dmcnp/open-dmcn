// The Sent self-copy round trip: a split envelope sealed to our own key, serialized the way
// the personal store holds it, opened again the way the Sent list does. The stored shape is
// a hand-written JSON mirror of the wire entry, so a field added to the wire (the CEK-wrap
// generation, `kdf`) is silently absent here unless something checks — and it was: every
// send between that field's arrival and this test opened as the legacy generation and was
// dropped from Sent with an OperationError.
import { describe, it, expect } from 'vitest';
import { generateIdentityKeyPair, importEd25519PrivateKey, importX25519PrivateKey } from '../crypto/keys';
import { encryptSplit } from '../crypto/split';
import { KDF_V2 } from '../crypto/sealVersion';
import { encodeStoredHeader, openStoredHeader, type StoredHeader } from './sentStore';

async function selfSealed() {
  const kp = await generateIdentityKeyPair();
  const signKey = await importEd25519PrivateKey(kp.ed25519Private.slice(0, 32));
  const derive = await importX25519PrivateKey(kp.x25519Private);
  const env = await encryptSplit({
    version: 1,
    messageId: crypto.getRandomValues(new Uint8Array(16)),
    threadId: crypto.getRandomValues(new Uint8Array(16)),
    senderAddress: 'me@dmcn.localhost',
    senderPublicKey: kp.ed25519Public,
    senderSignKey: signKey,
    recipientAddress: 'me@dmcn.localhost',
    to: ['you@dmcn.localhost'],
    sentAt: 1_760_000_000,
    subject: 'Kept in Sent',
    bodyText: 'The copy nobody else can read.',
    recipients: [{ deviceId: kp.deviceId, x25519Pub: kp.x25519Public }],
  });
  return { env, derive, pub: kp.x25519Public };
}

describe('Sent self-copy storage', () => {
  it('keeps the seal generation and opens the header it stored', async () => {
    const { env, derive, pub } = await selfSealed();
    const stored = encodeStoredHeader(env);
    expect(stored.recipients[0].kdf).toBe(KDF_V2);

    const { entry, header } = await openStoredHeader(stored, derive, pub);
    expect(header.subject).toBe('Kept in Sent');
    expect(header.to).toEqual(['you@dmcn.localhost']);
    expect(entry.recipients[0].kdf).toBe(KDF_V2);
  });

  it('opens a row stored without its generation by trying each one', async () => {
    const { env, derive, pub } = await selfSealed();
    const stored = encodeStoredHeader(env);
    const legacy: StoredHeader = {
      ...stored,
      recipients: stored.recipients.map(r => { const legacyRow = { ...r }; delete legacyRow.kdf; return legacyRow; }),
    };
    const { entry, header } = await openStoredHeader(legacy, derive, pub);
    expect(header.subject).toBe('Kept in Sent');
    // The generation that opened it is what the body decrypt must use next.
    expect(entry.recipients[0].kdf).toBe(KDF_V2);
  });

  it('refuses a row it cannot open under any generation', async () => {
    const { env, derive } = await selfSealed();
    const other = await generateIdentityKeyPair();
    await expect(openStoredHeader(encodeStoredHeader(env), derive, other.x25519Public)).rejects.toThrow();
  });
});
