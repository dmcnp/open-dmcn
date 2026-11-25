// Passcodes: the secret that opens an exported key file, generated here rather than chosen.
//
// A backup has to fail independently of the thing it backs up. A passkey-protected backup does
// not: lose the passkey and the backup goes with it, which is exactly how the first lost mailbox
// on a live dmcnd happened. A passphrase is independent, but people pick weak ones and forget
// what they typed. A generated passcode avoids both: it is random, and the person is asked to
// save it (to a password manager, or on paper) at the moment the file is made.
//
// The code is 25 Crockford base32 characters, 125 bits, shown in five groups of five, in
// lowercase: shown in capitals it reads as if it must be typed in capitals, and it need not be. At that
// entropy a memory-hard KDF buys nothing, so the file key is HKDF-SHA256 of the code; the salt
// is per file, and the info string keeps this key from ever being the same as any other
// derivation of the same bytes.

import { bufferSource } from './bytes';

// Crockford base32: no i, l, o or u, so the code survives being read aloud or handwritten.
const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';
const GROUPS = 5;
const GROUP_LEN = 5;
export const PASSCODE_LENGTH = GROUPS * GROUP_LEN;

const HKDF_INFO = new TextEncoder().encode('dmcn-key-export-passcode-v1');

// generatePasscode returns a fresh passcode, already grouped for display.
export function generatePasscode(): string {
  // 256 is a multiple of 32, so masking a random byte is uniform: no modulo bias to reject.
  const bytes = crypto.getRandomValues(new Uint8Array(PASSCODE_LENGTH));
  let out = '';
  for (const b of bytes) out += ALPHABET[b & 31];
  return formatPasscode(out);
}

// normalizePasscode turns whatever the person typed or pasted back into the canonical 25
// lowercase characters: case, spaces and dashes do not matter, and the letters Crockford folds
// onto digits (o→0, i and l→1) are folded. Throws when what is left is not a code.
export function normalizePasscode(input: string): string {
  const s = input
    .toLowerCase()
    .replace(/[\s-]/g, '')
    .replace(/o/g, '0')
    .replace(/[il]/g, '1');
  if (s.length !== PASSCODE_LENGTH || [...s].some(c => !ALPHABET.includes(c))) {
    throw new Error(`a passcode is ${PASSCODE_LENGTH} letters and digits, like ${formatPasscode('x'.repeat(PASSCODE_LENGTH))}`);
  }
  return s;
}

export function formatPasscode(code: string): string {
  const groups: string[] = [];
  for (let i = 0; i < code.length; i += GROUP_LEN) groups.push(code.slice(i, i + GROUP_LEN));
  return groups.join('-');
}

// passcodeKey derives the AES-256-GCM key a code opens. It accepts the code in any form the
// person might type it (see normalizePasscode).
export async function passcodeKey(code: string, salt: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', bufferSource(new TextEncoder().encode(normalizePasscode(code))), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: bufferSource(salt), info: bufferSource(HKDF_INFO) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    usage,
  );
}
