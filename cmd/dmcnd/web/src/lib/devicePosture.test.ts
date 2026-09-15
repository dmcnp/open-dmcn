import { beforeEach, describe, expect, it, vi } from 'vitest';

// The posture decides where a working handle is stored, and the old arrangement made its ABSENCE
// mean "delete the keys". So what matters here is the direction of every fallback: an unreadable
// store, a missing record and a missing mirror must all land on locking, never on the answer that
// destroys handles.

const store = new Map<string, unknown>();
vi.mock('./crypto/idb', () => ({
  DEVICE_STORE: 'device',
  idbGet: vi.fn(async (_s: string, k: string) => store.get(k)),
  idbPut: vi.fn(async (_s: string, k: string, v: unknown) => { store.set(k, v); }),
}));
vi.mock('./appContext', () => ({ storageKey: (n: string) => n }));

// A localStorage stand-in; the module only ever uses these three calls.
const mirror = new Map<string, string>();
vi.stubGlobal('localStorage', {
  getItem: (k: string) => mirror.get(k) ?? null,
  setItem: (k: string, v: string) => { mirror.set(k, v); },
  removeItem: (k: string) => { mirror.delete(k); },
});

async function freshModule() {
  vi.resetModules();
  return import('./devicePosture');
}

beforeEach(() => {
  store.clear();
  mirror.clear();
});

describe('devicePosture', () => {
  it('locks by default, before anything is loaded', async () => {
    const m = await freshModule();
    expect(m.isLockOnLeave()).toBe(true);
  });

  it('reads a stored choice', async () => {
    store.set('posture', { lockOnLeave: false });
    const m = await freshModule();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(false);
  });

  // The failure that caused the bug: the record is gone. It must NOT read as "the user turned
  // persistence off", because that is what used to delete every persistent handle.
  it('falls back to locking when nothing is stored', async () => {
    const m = await freshModule();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(true);
  });

  it('round-trips a choice through the store and the mirror', async () => {
    const m = await freshModule();
    await m.setLockOnLeave(false);
    expect(m.isLockOnLeave()).toBe(false);
    expect(store.get('posture')).toEqual({ lockOnLeave: false });
    expect(mirror.get('dmcn_lock_on_leave')).toBe('false');
  });

  it('uses the mirror when the store cannot be read', async () => {
    mirror.set('dmcn_lock_on_leave', 'false');
    const idb = await import('./crypto/idb');
    vi.mocked(idb.idbGet).mockRejectedValueOnce(new Error('no indexeddb'));
    const m = await freshModule();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(false);
  });
});

describe('migrateLegacyPosture', () => {
  // Someone who turned "stay signed in" ON said something deliberate; losing it would put them
  // back behind an unlock they had opted out of.
  it('carries an explicit opt-out of locking across', async () => {
    mirror.set('dmcn_stay_signed_in', 'true');
    const m = await freshModule();
    await m.migrateLegacyPosture();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(false);
    expect(mirror.has('dmcn_stay_signed_in')).toBe(false);
  });

  // "false" was the old default AND what an evaporated preference looked like. It says nothing,
  // so it is not carried over — the safe default stands.
  it('ignores a value that could just be the old default', async () => {
    mirror.set('dmcn_stay_signed_in', 'false');
    const m = await freshModule();
    await m.migrateLegacyPosture();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(true);
  });

  it('does not overturn a choice already made in the new store', async () => {
    store.set('posture', { lockOnLeave: true });
    mirror.set('dmcn_stay_signed_in', 'true');
    const m = await freshModule();
    await m.migrateLegacyPosture();
    await m.initDevicePosture();
    expect(m.isLockOnLeave()).toBe(true);
  });
});
