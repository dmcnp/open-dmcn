import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { DeviceKey } from '../crypto/deviceKey';

// What an approval sends, checked at the two calls it makes. Both cases here are ones where the
// wrong request still succeeds at the relay and does harm: an approval sent without this
// device's signature enrols the newcomer as the mailbox's first device, and an approval dated by
// a device clock a few minutes out is refused every time.

const calls: { path: string; body: Record<string, unknown> }[] = [];
let device: DeviceKey | null = null;
let serverTime: number | undefined;
const plain = (): unknown => ({ device: {}, genesis: false });
// The op travels on the challenge; the second call only answers it.
let asked: Record<string, unknown> = {};
let complete: (body: Record<string, unknown>) => unknown = plain;

vi.mock('./client', async importOriginal => ({
  ...(await importOriginal<typeof import('./client')>()),
  postJSONAs: async (_as: unknown, path: string, body: Record<string, unknown>) => {
    calls.push({ path, body });
    if (path.endsWith('/challenge')) {
      asked = body;
      return { correlation_id: 'c1', nonce: btoa(String.fromCharCode(...new Uint8Array(32))), server_time: serverTime };
    }
    return complete(asked);
  },
}));

vi.mock('../crypto/deviceKey', async importOriginal => ({
  ...(await importOriginal<typeof import('../crypto/deviceKey')>()),
  loadDeviceKey: async () => device,
  getOrCreateDeviceKey: async () => device,
}));

const { enrolDevice, ensureDeviceEnrolled, retireDevice, NoDeviceKeyError } = await import('./deviceRegistry');
const { ApiError } = await import('./client');
const { toBase64 } = await import('../crypto/keys');
const { deviceApprovalBytes } = await import('../crypto/deviceKey');

const account = { address: 'a@example.test', sign: async () => new Uint8Array(64) };
const newcomer = new Uint8Array(32).fill(7);

beforeEach(() => {
  calls.length = 0;
  device = null;
  serverTime = undefined;
  complete = plain;
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

// Opening the app checks that this browser is on the mailbox. A device that is already on it
// must not ask to join again: the relay refuses that, on every open, for nothing.
describe('putting this browser on the mailbox', () => {
  const key: DeviceKey = { publicKey: new Uint8Array(32).fill(1), sign: async () => new Uint8Array(64) };
  const ops = () => calls.filter(c => c.path.endsWith('/challenge')).map(c => c.body.op);

  it('asks for nothing when the list already has this device', async () => {
    device = key;
    complete = () => ({ devices: [{ public: toBase64(key.publicKey), enrolled_at: 1 }] });
    expect(await ensureDeviceEnrolled(account)).toEqual({ state: 'enrolled', genesis: false });
    expect(ops()).toEqual(['device_list']);
  });

  it('asks to join a mailbox with no device on it', async () => {
    device = key;
    complete = body => (body.op === 'device_list' ? { devices: [] } : { genesis: true });
    expect(await ensureDeviceEnrolled(account)).toEqual({ state: 'enrolled', genesis: true });
    expect(ops()).toEqual(['device_list', 'device_enroll']);
  });

  it('asks to join when its only entry is a removed one', async () => {
    device = key;
    complete = body => {
      if (body.op === 'device_list') return { devices: [{ public: toBase64(key.publicKey), enrolled_at: 1, retired_at: 2 }] };
      throw new ApiError('refused', 403, 'device_approval_required');
    };
    expect(await ensureDeviceEnrolled(account)).toEqual({ state: 'needs-approval' });
  });

  it('asks to join when it is refused the list, and reports that answer', async () => {
    device = key;
    complete = body => {
      throw new ApiError('refused', 403, body.op === 'device_list' ? 'device_not_enrolled' : 'device_approval_required');
    };
    expect(await ensureDeviceEnrolled(account)).toEqual({ state: 'needs-approval' });
    expect(ops()).toEqual(['device_list', 'device_enroll']);
  });

  it('stops at the list on a server with no registry', async () => {
    device = key;
    complete = () => { throw new ApiError('no registry', 501, 'unsupported'); };
    expect(await ensureDeviceEnrolled(account)).toEqual({ state: 'no-registry' });
    expect(ops()).toEqual(['device_list']);
  });
});
