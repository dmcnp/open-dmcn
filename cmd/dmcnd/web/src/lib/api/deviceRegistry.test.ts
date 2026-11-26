import { describe, it, expect } from 'vitest';
import { classifyEnrolment, classifyRecovery, describeBrowser, deviceStanding, forgetRecovery, isAlreadyEnrolled, isNoRegistry, isUnapprovedDevice, MAX_DEVICE_LABEL, openDeviceLabel, rememberedRecovery, rememberRecovery, sealDeviceLabel, waitingDevices, type DeviceRecord } from './deviceRegistry';
import { toBase64 } from '../crypto/keys';
import { ApiError } from './bearer';
import type { WorkingKeys } from '../crypto/workingKeys';

// Putting this browser on the registry doubles as the probe for whether it is already there, and
// it has to: knowing would mean listing the registry, and listing is itself gated on being
// enrolled. So the relay's answer to "let me in" is what distinguishes the states.
//
// Getting this classification wrong is quiet and bad in both directions. Read "already enrolled"
// as a failure and every app open shows a device that cannot get in; read "needs approval" as
// success and a browser that is shut out believes it is fine until the first mailbox call fails.
describe('classifyEnrolment', () => {
  it('treats an existing enrolment as success, not an error', () => {
    // Verbatim what the browser sees: the relay's refusal, wrapped by the mailbox proxy.
    const err = new Error(
      'device enrol failed: relay: mailbox-ext: INVALID_REQUEST: this device is already enrolled',
    );
    expect(classifyEnrolment(err)).toEqual({ state: 'enrolled', genesis: false });
  });

  it('recognises a claimed registry as needing approval rather than as an outage', () => {
    // Verbatim relay.ErrDeviceApprovalRequired, wrapped by the mailbox proxy. Note it also
    // contains the word "already": matching loosely on that would read this as "enrolled", which
    // is the exact mis-read this test exists to prevent.
    const err = new Error(
      'device enrol failed: relay: enrolment needs approval from a device already on this mailbox',
    );
    expect(classifyEnrolment(err)).toEqual({ state: 'needs-approval' });
  });

  it('leaves anything else as unavailable, so a bad minute of network is not a verdict', () => {
    // An unreachable fleet says nothing about whether this device belongs; the next open asks
    // again. Mistaking it for "shut out" would send someone to re-pair a device that was fine.
    const err = new Error('fetch failed');
    expect(classifyEnrolment(err)).toEqual({ state: 'unavailable', error: err });
  });

  it('does not mistake a non-Error rejection for a state', () => {
    expect(classifyEnrolment('something threw a string')).toMatchObject({ state: 'unavailable' });
  });
});

// A server says which refusal it is with a code, and both servers use the same ones. The words
// beside the code are for a person and may change, so none of these cases can be read from them.
describe('refusals read by code', () => {
  const refusal = (status: number, code: string) => new ApiError('whatever the server chose to say', status, code);

  it('reads an enrolment answer from its code', () => {
    expect(classifyEnrolment(refusal(409, 'device_already_enrolled'))).toEqual({ state: 'enrolled', genesis: false });
    expect(classifyEnrolment(refusal(403, 'device_approval_required'))).toEqual({ state: 'needs-approval' });
  });

  it('carries on without a registry where the server keeps none', () => {
    expect(classifyEnrolment(refusal(501, 'unsupported'))).toEqual({ state: 'no-registry' });
    // A server from before the registry does not know the op at all.
    expect(classifyEnrolment(new ApiError('unknown mailbox op: device_enroll', 400))).toEqual({ state: 'no-registry' });
  });

  it('does not take some other refusal for one of these', () => {
    expect(classifyEnrolment(refusal(403, 'auth_failed'))).toMatchObject({ state: 'unavailable' });
    expect(classifyEnrolment(refusal(403, 'device_on_probation'))).toMatchObject({ state: 'unavailable' });
    expect(isUnapprovedDevice(refusal(403, 'auth_failed'))).toBe(false);
  });

  it('reads a recovery answer from its code', () => {
    expect(classifyRecovery(refusal(403, 'device_recovery_disabled'))).toEqual({ state: 'disabled' });
    expect(classifyRecovery(refusal(409, 'device_already_enrolled'))).toEqual({ state: 'already-asked' });
    expect(classifyRecovery(refusal(403, 'device_approval_required'))).toEqual({ state: 'cancelled' });
  });

  it('knows a mailbox call refused for want of an enrolled device', () => {
    expect(isUnapprovedDevice(refusal(403, 'device_not_enrolled'))).toBe(true);
  });
});

describe('answers a caller acts on', () => {
  it('knows a device that is already on the mailbox, by code or by the older sentence', () => {
    expect(isAlreadyEnrolled(new ApiError('nope', 409, 'device_already_enrolled'))).toBe(true);
    expect(isAlreadyEnrolled(new ApiError('this device is already enrolled', 400))).toBe(true);
    expect(isAlreadyEnrolled(new ApiError('auth failed', 403, 'auth_failed'))).toBe(false);
  });

  it('knows a server with no registry, so the device list hides and does not report a failure', () => {
    expect(isNoRegistry(new ApiError('this relay does not keep a device registry', 501, 'unsupported'))).toBe(true);
    expect(isNoRegistry(new Error('this mailbox does not host a device registry'))).toBe(true);
    expect(isNoRegistry(new ApiError('could not read the device registry', 502, 'storage_failed'))).toBe(false);
  });
});

describe('isUnapprovedDevice', () => {
  it('recognises the relay refusing a browser that is not an enrolled device', () => {
    // Verbatim relay.ErrDeviceNotEnrolled as the mailbox proxy forwards it on a list.
    expect(isUnapprovedDevice(new Error('mailbox list failed: relay: this mailbox requires a proof from an enrolled device'))).toBe(true);
  });

  it('leaves every other failure alone, so an outage is not taken for a removal', () => {
    expect(isUnapprovedDevice(new Error('mailbox list failed: all relay hints unreachable'))).toBe(false);
    expect(isUnapprovedDevice(undefined)).toBe(false);
  });
});

describe('deviceStanding', () => {
  it('reads a record as removed, waiting out a recovery, or active', () => {
    expect(deviceStanding({ public: 'a', enrolled_at: 1, retired_at: 5 }, 10)).toBe('removed');
    expect(deviceStanding({ public: 'a', enrolled_at: 1, eligible_at: 20 }, 10)).toBe('waiting');
    expect(deviceStanding({ public: 'a', enrolled_at: 1, eligible_at: 5 }, 10)).toBe('active');
    expect(deviceStanding({ public: 'a', enrolled_at: 1 }, 10)).toBe('active');
  });
});

describe('device labels', () => {
  it('round-trips a name sealed to the account key, and trims it to a name', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair;
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const keys = { x25519Derive: pair.privateKey, x25519Public: pub } as unknown as WorkingKeys;
    const sealed = await sealDeviceLabel(`  Phone ${'x'.repeat(100)}  `, pub);
    expect(sealed).toBeDefined();
    const name = await openDeviceLabel(toBase64(sealed!), keys);
    expect(name).toBe(`Phone ${'x'.repeat(MAX_DEVICE_LABEL - 6)}`);
  });

  it('seals nothing for a blank name and reads nothing from an absent or foreign one', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as CryptoKeyPair;
    const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    expect(await sealDeviceLabel('   ', pub)).toBeUndefined();
    const keys = { x25519Derive: pair.privateKey, x25519Public: pub } as unknown as WorkingKeys;
    expect(await openDeviceLabel(undefined, keys)).toBe('');
    expect(await openDeviceLabel(toBase64(new TextEncoder().encode('not a sealed blob')), keys)).toBe('');
  });
});

describe('describeBrowser', () => {
  it('names the common browsers plainly', () => {
    expect(describeBrowser('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36')).toBe('Chrome on macOS');
    expect(describeBrowser('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1')).toBe('Safari on iPhone');
    expect(describeBrowser('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0')).toBe('Edge on Windows');
    expect(describeBrowser('Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0')).toBe('Firefox on Linux');
    expect(describeBrowser('Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36')).toBe('Chrome on Android');
    expect(describeBrowser('curl/8')).toBe('Web browser');
  });
});

// A recovery request has four answers, and the browser shows four different things. Each match is
// on the relay's own sentence (pinned on the Go side by TestDeviceErrorPhrasesTheBrowserMatches),
// as the mailbox proxy forwards it.
describe('classifyRecovery', () => {
  it('tells a domain that refuses recovery apart from a removed browser', () => {
    expect(classifyRecovery(new Error('device enrol failed: relay: this domain does not let a device join without approval'))).toEqual({ state: 'disabled' });
    expect(classifyRecovery(new Error('device enrol failed: relay: enrolment needs approval from a device already on this mailbox'))).toEqual({ state: 'cancelled' });
  });
  it('reads asking again as the earlier request standing', () => {
    expect(classifyRecovery(new Error('device enrol failed: relay: mailbox-ext: INVALID_REQUEST: this device is already enrolled'))).toEqual({ state: 'already-asked' });
  });
  it('keeps anything else as an outage', () => {
    expect(classifyRecovery(new Error('network down')).state).toBe('unavailable');
  });
  it('does not let the disabled answer read as an enrolment refusal', () => {
    // The disabled sentence must not be mistaken for "needs approval" by the enrolment probe.
    expect(classifyEnrolment(new Error('device enrol failed: relay: this domain does not let a device join without approval')).state).toBe('unavailable');
  });
});

describe('the remembered recovery date', () => {
  it('round-trips per address, and tolerates no storage at all', () => {
    const store = new Map<string, string>();
    const g = globalThis as unknown as { localStorage?: unknown };
    const prev = g.localStorage;
    g.localStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => { store.set(k, v); },
      removeItem: (k: string) => { store.delete(k); },
    };
    try {
      expect(rememberedRecovery('a@x')).toBeNull();
      rememberRecovery('a@x', 1_800_000_000);
      expect(rememberedRecovery('a@x')).toBe(1_800_000_000);
      expect(rememberedRecovery('b@x')).toBeNull();
      forgetRecovery('a@x');
      expect(rememberedRecovery('a@x')).toBeNull();
    } finally {
      g.localStorage = prev;
    }
    // In node there is no localStorage: nothing throws, nothing is remembered.
    expect(() => rememberRecovery('a@x', 5)).not.toThrow();
    expect(rememberedRecovery('a@x')).toBeNull();
  });
});

describe('waitingDevices', () => {
  it('keeps only recovery requests still inside their wait', () => {
    const now = 1_800_000_000;
    const d = (over: Partial<DeviceRecord>): DeviceRecord => ({ public: 'k', enrolled_at: now - 100, ...over });
    const list = [d({ public: 'active' }), d({ public: 'waiting', eligible_at: now + 3600 }), d({ public: 'done', eligible_at: now - 1 }), d({ public: 'gone', retired_at: now - 5, eligible_at: now + 3600 })];
    expect(waitingDevices(list, now).map(x => x.public)).toEqual(['waiting']);
  });
});
