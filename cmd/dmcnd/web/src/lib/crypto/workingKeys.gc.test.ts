import { beforeEach, describe, expect, it, vi } from 'vitest';

// The collector used to delete every persistent handle whenever the stay-signed-in flag read
// false — and that flag lived in localStorage while the handles lived in IndexedDB, so a browser
// that cleared the first and kept the second destroyed working keys on its own. This pins the rule
// that replaced it: a handle is dropped because something OBSERVABLE says it is unreachable, never
// because a preference is missing.

const rows = new Map<string, { address: string }>();
vi.mock('./idb', () => ({
  WORKING_STORE: 'working',
  idbGet: vi.fn(async (_s: string, k: string) => rows.get(k)),
  idbGetAllKeys: vi.fn(async () => [...rows.keys()]),
  idbPut: vi.fn(async (_s: string, k: string, v: { address: string }) => { rows.set(k, v); }),
  idbDelete: vi.fn(async (_s: string, k: string) => { rows.delete(k); }),
}));
vi.mock('./keys', () => ({ importEd25519PrivateKey: vi.fn(), importX25519PrivateKey: vi.fn() }));
vi.mock('./bytes', () => ({ bufferSource: (b: Uint8Array) => b }));

let lockOnLeave = true;
vi.mock('../devicePosture', () => ({ isLockOnLeave: () => lockOnLeave }));
vi.mock('../sessionLifetime', () => ({
  accountWorkingRef: (a: string) => `acct:${a}`,
  tabWorkingPrefix: () => 'tab:this:',
  workingKeyRef: (a: string) => (lockOnLeave ? `tab:this:${a}` : `acct:${a}`),
  parseTabWorkingRef: (k: string) => {
    if (!k.startsWith('tab:')) return null;
    const rest = k.slice(4);
    const sep = rest.indexOf(':');
    return sep < 0 ? { tabId: rest, address: null } : { tabId: rest.slice(0, sep), address: rest.slice(sep + 1) };
  },
}));

beforeEach(() => {
  rows.clear();
  lockOnLeave = true;
});

describe('gcWorkingHandles', () => {
  it('keeps persistent handles, whatever the posture says', async () => {
    const { gcWorkingHandles } = await import('./workingKeys');
    rows.set('acct:a@x.test', { address: 'a@x.test' });
    rows.set('acct:b@x.test', { address: 'b@x.test' });

    // The posture that used to mean "delete them all".
    lockOnLeave = true;
    await gcWorkingHandles(new Set(['this']));

    expect([...rows.keys()].sort()).toEqual(['acct:a@x.test', 'acct:b@x.test']);
  });

  it('still reaps handles belonging to a tab that is gone', async () => {
    const { gcWorkingHandles } = await import('./workingKeys');
    rows.set('tab:this:a@x.test', { address: 'a@x.test' });
    rows.set('tab:closed:b@x.test', { address: 'b@x.test' });

    await gcWorkingHandles(new Set(['this']));

    expect([...rows.keys()]).toEqual(['tab:this:a@x.test']);
  });

  it('drops keys in no recognised shape', async () => {
    const { gcWorkingHandles } = await import('./workingKeys');
    rows.set('identity', { address: 'a@x.test' });
    await gcWorkingHandles(new Set(['this']));
    expect([...rows.keys()]).toEqual([]);
  });
});

describe('applyLockPosture', () => {
  // Flipping the switch used to strand every open account: only the ref changed, so the next read
  // looked somewhere the handle had never been and reported "locked".
  it('carries handles over when locking is turned off', async () => {
    const { applyLockPosture } = await import('./workingKeys');
    rows.set('tab:this:a@x.test', { address: 'a@x.test' });

    lockOnLeave = false; // the switch has just been flipped
    await applyLockPosture();

    expect([...rows.keys()]).toEqual(['acct:a@x.test']);
  });

  it('carries them back when locking is turned on', async () => {
    const { applyLockPosture } = await import('./workingKeys');
    rows.set('acct:a@x.test', { address: 'a@x.test' });

    lockOnLeave = true;
    await applyLockPosture();

    expect([...rows.keys()]).toEqual(['tab:this:a@x.test']);
  });

  // A handle naming someone else is not this account's to move, and copying it would put one
  // account's key where another's is read from.
  it('leaves a handle that names a different account where it is', async () => {
    const { applyLockPosture } = await import('./workingKeys');
    rows.set('acct:a@x.test', { address: 'someone-else@x.test' });

    lockOnLeave = true;
    await applyLockPosture();

    expect([...rows.keys()]).toEqual(['acct:a@x.test']);
  });
});
