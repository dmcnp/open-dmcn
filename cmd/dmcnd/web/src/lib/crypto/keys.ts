// Ed25519 key generation and import/export
// X25519 key generation and import/export

export interface IdentityKeyPair {
  ed25519Public: Uint8Array;   // 32 bytes
  ed25519Private: Uint8Array;  // 64 bytes (seed+public for Ed25519)
  x25519Public: Uint8Array;    // 32 bytes
  x25519Private: Uint8Array;   // 32 bytes
  deviceId: Uint8Array;        // 16 bytes UUID
  createdAt: number;           // Unix seconds
}

// PKCS8 for Ed25519: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes seed>
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// PKCS8 for X25519: 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 <32 bytes>
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

// Extract raw Ed25519 seed (32 bytes) from PKCS8
function extractEd25519Seed(pkcs8: Uint8Array): Uint8Array {
  // The seed starts at offset 16
  return pkcs8.slice(16, 48);
}

// Extract raw X25519 private key (32 bytes) from PKCS8
function extractX25519Private(pkcs8: Uint8Array): Uint8Array {
  return pkcs8.slice(16, 48);
}

export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  // Generate Ed25519 key pair
  const ed25519Key = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const ed25519Pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', ed25519Key.privateKey));
  const ed25519PubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519Key.publicKey));

  // Extract 32-byte seed from PKCS8
  const ed25519Seed = extractEd25519Seed(ed25519Pkcs8);

  // Build Go-compatible Ed25519 private key: 64 bytes = seed || public
  const ed25519Private = new Uint8Array(64);
  ed25519Private.set(ed25519Seed, 0);
  ed25519Private.set(ed25519PubRaw, 32);

  // Generate X25519 key pair
  const x25519Key = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const x25519Pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', x25519Key.privateKey));
  const x25519PubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', x25519Key.publicKey));

  // Extract raw 32-byte X25519 private key from PKCS8
  const x25519Private = extractX25519Private(x25519Pkcs8);

  // Generate device UUID v4
  const deviceId = crypto.getRandomValues(new Uint8Array(16));
  deviceId[6] = (deviceId[6] & 0x0f) | 0x40;
  deviceId[8] = (deviceId[8] & 0x3f) | 0x80;

  return {
    ed25519Public: ed25519PubRaw,
    ed25519Private,
    x25519Public: x25519PubRaw,
    x25519Private,
    deviceId,
    createdAt: Math.floor(Date.now() / 1000),
  };
}

// Import Ed25519 private key from 32-byte seed
export async function importEd25519PrivateKey(seed: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, 16);
  return crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', false, ['sign']);
}

// Import Ed25519 public key from 32-byte raw key
export async function importEd25519PublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'Ed25519', false, ['verify']);
}

// Import X25519 private key from 32-byte raw key
export async function importX25519PrivateKey(raw: Uint8Array): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(X25519_PKCS8_PREFIX, 0);
  pkcs8.set(raw, 16);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
}

// Import X25519 public key from 32-byte raw key
export async function importX25519PublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
}

// keyPairFromPayloadJSON parses the canonical web key JSON (the same shape
// keyPairToPayloadJSON / the register + import flows produce) back into a key pair.
export function keyPairFromPayloadJSON(bytes: Uint8Array): IdentityKeyPair {
  const d = JSON.parse(new TextDecoder().decode(bytes));
  return {
    ed25519Public: fromBase64(d.ed25519_public),
    ed25519Private: fromBase64(d.ed25519_private),
    x25519Public: fromBase64(d.x25519_public),
    x25519Private: fromBase64(d.x25519_private),
    deviceId: fromBase64(d.device_id),
    createdAt: d.created_at,
  };
}

// keyPairToPayloadJSON renders the canonical web key JSON (the same shape the import +
// export flows lock into the encrypted keystore) — the inverse of keyPairFromPayloadJSON.
export function keyPairToPayloadJSON(kp: IdentityKeyPair): string {
  return JSON.stringify({
    ed25519_public: toBase64(kp.ed25519Public),
    ed25519_private: toBase64(kp.ed25519Private),
    x25519_public: toBase64(kp.x25519Public),
    x25519_private: toBase64(kp.x25519Private),
    device_id: toBase64(kp.deviceId),
    created_at: kp.createdAt,
  });
}

// Helper to convert Uint8Array to base64
export function toBase64(bytes: Uint8Array): string {
  // Build the binary string in chunks. `String.fromCharCode(...bytes)` spreads every
  // byte as a separate argument, which overflows the call stack ("Maximum call stack
  // size exceeded") once a message is large — e.g. an envelope carrying an attachment.
  // 0x8000 keeps each call well under the engine's argument limit.
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

// Helper to convert base64 to Uint8Array
export function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Hex encoding helpers
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
