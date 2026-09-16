import { beforeEach, describe, expect, it, vi } from 'vitest';

// Which accounts are unlocked in this page is a property of the PAGE. IndexedDB is how that
// survives a reload, not how it is known — and conflating the two meant a write that did not stick
// silently cost an account the user had just unlocked, which is how "one unlock opens all your
// mailboxes" became "one unlock opens one mailbox" on a platform that would not keep them.

vi.mock('./idb', () => ({
  WORKING_STORE: 'working',
  DEVICE_STORE: 'device',
  idbGet: vi.fn(async () => undefined),
  idbGetAllKeys: vi.fn(async () => []),
  idbPut: vi.fn(async () => undefined),
  idbDelete: vi.fn(async () => undefined),
}));
vi.mock('./keys', () => ({
  importEd25519PrivateKey: vi.fn(async () => ({}) as CryptoKey),
  importX25519PrivateKey: vi.fn(async () => ({}) as CryptoKey),
}));
vi.mock('./bytes', () => ({ bufferSource: (b: Uint8Array) => b }));
vi.mock('../devicePosture', () => ({ isLockOnLeave: () => true }));
vi.mock('../sessionLifetime', () => ({
  accountWorkingRef: (a: string) => `acct:${a}`,
  tabWorkingPrefix: () => 'tab:this:',
  workingKeyRef: (a: string) => `tab:this:${a}`,
  parseTabWorkingRef: () => null,
}));

const handles = (address: string) => ({ address }) as unknown as import('./workingKeys').WorkingKeys;

beforeEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
});

describe('probeHandleStorage', () => {
  // The verdict that decides whether persisting a handle is worth attempting at all. A handle is
  // only useful whole, so one key type failing to survive is the whole answer — which is what
  // WebKit does with the X25519 key a handle needs to decrypt anything.
  it('calls a browser unable to revive the whole handle not ok', async () => {
    const idb = await import('./idb');
    // Individually fine, the complete record unreadable — the shape of the real failure.
    vi.mocked(idb.idbGet).mockImplementation(async (_s: string, key: string) =>
      (key === 'probe:whole' ? undefined : { key: {}, ed25519Sign: {}, x25519Derive: {}, aliasRoot: {} }) as never);
    const m = await import('./workingKeys');
    const v = await m.probeHandleStorage();
    expect(v.ok).toBe(false);
    expect(v.detail).toContain('whole-handle=unreadable');
  });

  it('calls a browser that revives everything ok', async () => {
    const idb = await import('./idb');
    vi.mocked(idb.idbGet).mockImplementation(async () =>
      ({ key: {}, ed25519Sign: {}, x25519Derive: {}, aliasRoot: {} }) as never);
    const m = await import('./workingKeys');
    const v = await m.probeHandleStorage();
    expect(v.ok).toBe(true);
    expect(v.detail).toContain('whole-handle=ok');
  });
});

describe('the page-held unlocked set', () => {
  it('remembers an account and gives its handles back', async () => {
    const m = await import('./workingKeys');
    m.rememberLiveHandles(handles('a@x.test'));
    expect(m.liveHandles('a@x.test')?.address).toBe('a@x.test');
    expect(m.liveAddresses()).toEqual(['a@x.test']);
  });

  it('holds several at once — the whole point of one unlock', async () => {
    const m = await import('./workingKeys');
    for (const a of ['a@x.test', 'b@x.test', 'c@x.test']) m.rememberLiveHandles(handles(a));
    expect(m.liveAddresses().sort()).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
  });

  it('never answers for an account it was not given', async () => {
    const m = await import('./workingKeys');
    m.rememberLiveHandles(handles('a@x.test'));
    expect(m.liveHandles('b@x.test')).toBeNull();
  });

  // Signing one account out must not touch the others, which is what makes the switcher usable.
  it('forgets one account and keeps the rest', async () => {
    const m = await import('./workingKeys');
    m.rememberLiveHandles(handles('a@x.test'));
    m.rememberLiveHandles(handles('b@x.test'));
    m.forgetLiveHandles('a@x.test');
    expect(m.liveHandles('a@x.test')).toBeNull();
    expect(m.liveAddresses()).toEqual(['b@x.test']);
  });

  // Sign out of all, and the app lock. Leaving anything here would keep a locked account open.
  it('forgets everything at once', async () => {
    const m = await import('./workingKeys');
    m.rememberLiveHandles(handles('a@x.test'));
    m.rememberLiveHandles(handles('b@x.test'));
    await m.clearUnlockedHandles();
    expect(m.liveAddresses()).toEqual([]);
  });
});
