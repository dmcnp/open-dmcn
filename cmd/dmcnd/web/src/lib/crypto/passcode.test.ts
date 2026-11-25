import { describe, it, expect } from 'vitest';
import { generatePasscode, normalizePasscode, PASSCODE_LENGTH } from './passcode';
import { buildPasscodeExport, readExport } from './exportFile';
import { encryptKeys } from './keystore';
import { keyPairToPayloadJSON, toBase64, type IdentityKeyPair } from './keys';

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

// A fixed key pair: the round trip only needs bytes to come back unchanged, not valid curve points.
const KP: IdentityKeyPair = {
  ed25519Public: fill(32, 1),
  ed25519Private: fill(64, 2),
  x25519Public: fill(32, 3),
  x25519Private: fill(32, 4),
  deviceId: fill(16, 5),
  createdAt: 1_794_528_000,
};

describe('passcodes', () => {
  it('generates five groups of five lowercase Crockford base32 characters', () => {
    const code = generatePasscode();
    expect(code).toMatch(/^[0-9a-hjkmnp-tv-z]{5}(-[0-9a-hjkmnp-tv-z]{5}){4}$/);
    expect(normalizePasscode(code)).toHaveLength(PASSCODE_LENGTH);
  });

  it('does not repeat', () => {
    const seen = new Set(Array.from({ length: 200 }, generatePasscode));
    expect(seen.size).toBe(200);
  });

  it('accepts the code however it is typed back', () => {
    // Capitals, spaces instead of dashes, and the look-alike letters Crockford folds onto digits.
    expect(normalizePasscode('O1LIZ ABCDE FGHJK MNPQR STVWX'))
      .toBe(normalizePasscode('0111z-abcde-fghjk-mnpqr-stvwx'));
  });

  it('refuses what is not a code, with a message saying what one looks like', () => {
    expect(() => normalizePasscode('ABCDE-FGHJK')).toThrow(/25 letters and digits/);
    expect(() => normalizePasscode('UUUUU-UUUUU-UUUUU-UUUUU-UUUUU')).toThrow(/25 letters and digits/);
  });
});

describe('passcode-protected key files', () => {
  it('round-trips through the file with the code in any typed form', async () => {
    const code = generatePasscode();
    const exp = await buildPasscodeExport('alice@mesh.example', KP, code);
    expect(exp.authMethod).toBe('passcode');
    expect(exp.bundle.kdf).toBe('hkdf-sha256');

    const typed = code.toUpperCase().replace(/-/g, ' ');
    const { kp } = await readExport(JSON.parse(JSON.stringify(exp)), { password: typed });
    expect(keyPairToPayloadJSON(kp)).toBe(keyPairToPayloadJSON(KP));
  });

  it('says a wrong code is wrong, rather than failing inside the cipher', async () => {
    const exp = await buildPasscodeExport('alice@mesh.example', KP, generatePasscode());
    await expect(readExport(exp, { password: generatePasscode() })).rejects.toThrow(/does not open this file/);
  });

  it('salts each file, so one code never makes two identical files', async () => {
    const code = generatePasscode();
    const a = await buildPasscodeExport('alice@mesh.example', KP, code);
    const b = await buildPasscodeExport('alice@mesh.example', KP, code);
    expect(a.bundle.salt).not.toBe(b.bundle.salt);
    expect(a.bundle.ciphertext).not.toBe(b.bundle.ciphertext);
  });

  it('still reads a passphrase backup made before passcodes', async () => {
    const payload = new TextEncoder().encode(keyPairToPayloadJSON(KP));
    const legacy = {
      format: 'dmcn-keystore-export' as const,
      version: 1 as const,
      address: 'alice@mesh.example',
      ed25519Public: toBase64(KP.ed25519Public),
      authMethod: 'password' as const,
      bundle: await encryptKeys(payload, 'correct horse battery staple'),
    };
    const { kp } = await readExport(legacy, { password: 'correct horse battery staple' });
    expect(keyPairToPayloadJSON(kp)).toBe(keyPairToPayloadJSON(KP));
  });
});
