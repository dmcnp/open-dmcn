import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, BearerSession, fetchJSON } from './bearer';

const json = (status: number, body: unknown) =>
  new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

afterEach(() => { vi.unstubAllGlobals(); });

describe('BearerSession', () => {
  it('single-flights concurrent renewals and stores the minted token', async () => {
    const s = new BearerSession();
    let mints = 0;
    s.setMinter(async () => { mints++; await new Promise(r => setTimeout(r, 5)); return 'tok-' + mints; });
    const [a, b, c] = await Promise.all([s.renew(), s.renew(), s.renew()]);
    expect([a, b, c]).toEqual(['tok-1', 'tok-1', 'tok-1']);
    expect(mints).toBe(1);
    expect(s.get()).toBe('tok-1');
  });
  it('drops the token when the minter changes identity', () => {
    const s = new BearerSession();
    s.set('old');
    s.setMinter(async () => 'new');
    expect(s.get()).toBe('old');
    s.setMinter(async () => 'new', { dropToken: true });
    expect(s.get()).toBeNull();
  });
});

describe('fetchJSON', () => {
  it('attaches the bearer, renews once on 401 and retries with the fresh token', async () => {
    const seen: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>)['Authorization'] ?? '';
      seen.push(auth);
      return auth === 'Bearer fresh' ? json(200, { ok: true }) : json(401, { error: 'expired' });
    }));
    const s = new BearerSession();
    s.set('stale');
    s.setMinter(async () => 'fresh');
    await expect(fetchJSON('GET', '/x', undefined, { session: s })).resolves.toEqual({ ok: true });
    expect(seen).toEqual(['Bearer stale', 'Bearer fresh']);
    expect(s.get()).toBe('fresh');
  });
  it('retries at most once and surfaces the server error shape', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => json(401, { error: 'nope', code: 'no_session' })));
    const s = new BearerSession();
    s.setMinter(async () => 'again');
    const err = (await fetchJSON('GET', '/x', undefined, { session: s }).catch(e => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(401);
    expect(err.code).toBe('no_session');
    expect((fetch as unknown as { mock: { calls: unknown[] } }).mock.calls.length).toBe(2);
  });
  it('mints before the first call when asked and never renews an explicit token', async () => {
    const auths: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => {
      auths.push((init.headers as Record<string, string>)['Authorization'] ?? '');
      return auths.length === 1 ? json(204, null) : json(401, { error: 'expired' });
    }));
    const s = new BearerSession();
    s.setMinter(async () => 'minted');
    await expect(fetchJSON('POST', '/first', { a: 1 }, { session: s, mintIfMissing: true })).resolves.toBeUndefined();
    await expect(fetchJSON('POST', '/second', {}, { session: s, token: 'explicit' })).rejects.toBeInstanceOf(ApiError);
    expect(auths).toEqual(['Bearer minted', 'Bearer explicit']);
  });
});
