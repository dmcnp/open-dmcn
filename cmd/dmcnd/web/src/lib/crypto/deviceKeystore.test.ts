import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateIdentityKeyPair, keyPairToPayloadJSON, toBase64 } from './keys';
import { encryptKeys } from './keystore';

// The shared unlock stores the KEY to each account's keystore, never a second copy of the identity
// — so what is pinned here is that one secret opens every attached account by way of the bundle
// that was already there, that a stale key is reported as unattached rather than silently skipped,
// and that detaching leaves the account exactly as it found it.
//
// The password path only: the passkey path is a WebAuthn ceremony with no headless equivalent.

const device = new Map<string, unknown>();
const accounts = new Map<string, unknown>();

vi.mock('./idb', () => ({
  DEVICE_STORE: 'device',
  idbGet: vi.fn(async (_s: string, k: string) => device.get(k)),
  idbPut: vi.fn(async (_s: string, k: string, v: unknown) => { device.set(k, v); }),
  idbDelete: vi.fn(async (_s: string, k: string) => { device.delete(k); }),
}));
vi.mock('./localKeystore', () => ({
  loadLocalKeystore: vi.fn(async (a: string) => accounts.get(a) ?? null),
}));
vi.mock('./passkey', () => ({ createPasskeyPRF: vi.fn(), unlockPasskeyPRF: vi.fn() }));

const DEVICE_PW = 'one door for this device';
const ACCOUNT_PW = 'this account only';

// A real account keystore: the identity genuinely encrypted under its own password, so the
// device-unlock path has to go all the way through to key bytes that match.
async function provision(address: string) {
  const kp = await generateIdentityKeyPair();
  const bundle = await encryptKeys(new TextEncoder().encode(keyPairToPayloadJSON(kp)), ACCOUNT_PW);
  accounts.set(address, { address, bundle, authMethod: 'password' });
  return kp;
}

async function bundleKeyOf(address: string) {
  const { bundleKeyBytes } = await import('./keystore');
  const ks = accounts.get(address) as { bundle: Parameters<typeof bundleKeyBytes>[0] };
  return bundleKeyBytes(ks.bundle, ACCOUNT_PW);
}

beforeEach(() => {
  device.clear();
  accounts.clear();
});

describe('deviceKeystore', () => {
  it('opens every attached account from one secret, through their own keystores', async () => {
    const m = await import('./deviceKeystore');
    const alice = await provision('a@x.test');
    const bob = await provision('b@x.test');

    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await m.attachAccount({ address: 'b@x.test', bundleKey: await bundleKeyOf('b@x.test'), password: DEVICE_PW });

    expect(await m.attachedAddresses()).toEqual(['a@x.test', 'b@x.test']);
    const opened = await m.unlockDevice({ password: DEVICE_PW });
    expect(Object.keys(opened).sort()).toEqual(['a@x.test', 'b@x.test']);
    expect(toBase64(opened['a@x.test'].ed25519Private)).toBe(toBase64(alice.ed25519Private));
    expect(toBase64(opened['b@x.test'].x25519Private)).toBe(toBase64(bob.x25519Private));
  }, 60_000);

  // The point of the whole design: no second wrapping of the identity is created.
  it('stores a key, not another copy of the identity', async () => {
    const m = await import('./deviceKeystore');
    const kp = await provision('a@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });

    // Whatever the device secret holds, it decrypts to 32 bytes — a key — and not to anything
    // containing the private key it ultimately reaches.
    const { decryptKeys } = await import('./keystore');
    const stored = (await m.loadDeviceKeystore())!.entries['a@x.test'];
    const plain = await decryptKeys(stored.key, DEVICE_PW);
    expect(plain).toHaveLength(32);
    expect(toBase64(plain)).not.toContain(toBase64(kp.ed25519Private).slice(0, 16));
  }, 60_000);

  it('opens nothing on the wrong device password', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await expect(m.unlockDevice({ password: 'not it' })).rejects.toThrow();
  }, 60_000);

  it('asks for a password rather than assuming one', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await expect(m.unlockDevice()).rejects.toBeInstanceOf(m.DevicePasswordRequiredError);
  }, 60_000);

  // Re-wrapping an account (password change, re-import, re-pair) mints a new bundle, and the
  // stored key opens nothing. It must read as detached rather than be quietly skipped, or the UI
  // promises an unlock that cannot happen.
  it('reports an account as unattached once its keystore is re-wrapped', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await provision('b@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await m.attachAccount({ address: 'b@x.test', bundleKey: await bundleKeyOf('b@x.test'), password: DEVICE_PW });

    await provision('a@x.test'); // the same address, a brand-new bundle

    expect(await m.isAttached('a@x.test')).toBe(false);
    expect(await m.attachedAddresses()).toEqual(['b@x.test']);
    expect(Object.keys(await m.unlockDevice({ password: DEVICE_PW }))).toEqual(['b@x.test']);
  }, 60_000);

  it('reports an account as unattached once it is gone from this device', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    accounts.delete('a@x.test');
    expect(await m.attachedAddresses()).toEqual([]);
  }, 60_000);

  it('detaching removes that account and keeps the others', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await provision('b@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await m.attachAccount({ address: 'b@x.test', bundleKey: await bundleKeyOf('b@x.test'), password: DEVICE_PW });

    await m.detachAccount('a@x.test');
    expect(await m.attachedAddresses()).toEqual(['b@x.test']);
    // And the detached account is untouched: its own password still opens its own keystore.
    const { decryptKeys } = await import('./keystore');
    const ks = accounts.get('a@x.test') as { bundle: Parameters<typeof decryptKeys>[0] };
    await expect(decryptKeys(ks.bundle, ACCOUNT_PW)).resolves.toBeInstanceOf(Uint8Array);
  }, 60_000);

  // An empty shell would still offer "unlock this device" and open nothing.
  it('detaching the last account removes the secret entirely', async () => {
    const m = await import('./deviceKeystore');
    await provision('a@x.test');
    await m.attachAccount({
      address: 'a@x.test', bundleKey: await bundleKeyOf('a@x.test'),
      create: { authMethod: 'password', password: DEVICE_PW },
    });
    await m.detachAccount('a@x.test');
    expect(await m.loadDeviceKeystore()).toBeNull();
    expect(await m.attachedAddresses()).toEqual([]);
  }, 60_000);
});
