import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { DeviceKey } from '../crypto/deviceKey';

// What an approval sends, checked at the two calls it makes. Both cases here are ones where the
// wrong request still succeeds at the relay and does harm: an approval sent without this
// device's signature enrols the newcomer as the mailbox's first device, and an approval dated by
// a device clock a few minutes out is refused every time.

const calls: { path: string; body: Record<string, unknown> }[] = [];
let device: DeviceKey | null = null;
let serverTime: number | undefined;

vi.mock('./client', async importOriginal => ({
  ...(await importOriginal<typeof import('./client')>()),
  postJSONAs: async (_as: unknown, path: string, body: Record<string, unknown>) => {
    calls.push({ path, body });
    if (path.endsWith('/challenge')) {
      return { correlation_id: 'c1', nonce: btoa(String.fromCharCode(...new Uint8Array(32))), server_time: serverTime };
    }
    return { device: {}, genesis: false };
  },
}));

vi.mock('../crypto/deviceKey', async importOriginal => ({
  ...(await importOriginal<typeof import('../crypto/deviceKey')>()),
  loadDeviceKey: async () => device,
}));

const { enrolDevice, retireDevice, NoDeviceKeyError } = await import('./deviceRegistry');
const { deviceApprovalBytes } = await import('../crypto/deviceKey');

const account = { address: 'a@example.test', sign: async () => new Uint8Array(64) };
const newcomer = new Uint8Array(32).fill(7);

beforeEach(() => {
  calls.length = 0;
  device = null;
  serverTime = undefined;
});

describe('an op that needs this device to sign', () => {
  it('is not sent from a browser with no device key', async () => {
    await expect(enrolDevice(account.address, account, newcomer, 1000)).rejects.toBeInstanceOf(NoDeviceKeyError);
    await expect(retireDevice(account.address, account, newcomer)).rejects.toBeInstanceOf(NoDeviceKeyError);
    expect(calls).toEqual([]);
  });
});

describe('the date on an approval', () => {
  const signed: Uint8Array[] = [];
  const key: DeviceKey = {
    publicKey: new Uint8Array(32).fill(1),
    sign: async data => { signed.push(data); return new Uint8Array(64); },
  };

  it('is the server clock, and the signature covers the same date', async () => {
    device = key; serverTime = 5000; signed.length = 0;
    await enrolDevice(account.address, account, newcomer, 1000);
    expect(calls[1].body.approved_at).toBe(5000);
    expect(signed).toContainEqual(deviceApprovalBytes(account.address, newcomer, new Uint8Array(32), 5000));
  });

  it('falls back to this device for a server that sends no clock', async () => {
    device = key; signed.length = 0;
    await enrolDevice(account.address, account, newcomer, 1000);
    expect(calls[1].body.approved_at).toBe(1000);
  });

  it('stays the credential date when one is supplied', async () => {
    device = key; serverTime = 5000;
    await enrolDevice(account.address, account, newcomer, 1000, undefined, new Uint8Array([1]));
    expect(calls[1].body.approved_at).toBe(1000);
  });
});
