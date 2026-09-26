import { describe, it, expect } from 'vitest';
import { classifyEnrolment, describeBrowser, deviceStanding, isUnapprovedDevice, MAX_DEVICE_LABEL, openDeviceLabel, sealDeviceLabel } from './deviceRegistry';
import { toBase64 } from '../crypto/keys';
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
