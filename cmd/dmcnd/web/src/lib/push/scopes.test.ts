import { describe, expect, it } from 'vitest';
import { scopeIdFor, scopeIdOf, scopePathFor } from './scopes';

// The scope id is the one thing tying a browser's notification registration to a mailbox, and it is
// derived in two places from two different sources: from the unlocked handle while the app runs,
// and from the plaintext half of the keystore while the account is locked. If those ever disagreed,
// a tapped notification would route to the wrong account or to none, so the agreement is pinned
// here rather than assumed.

const KEY_A = new Uint8Array(32).fill(7);
const KEY_B = Uint8Array.from({ length: 32 }, (_, i) => i);

describe('scopeIdFor', () => {
  it('is stable for one key and different for another', async () => {
    const a = await scopeIdFor(KEY_A);
    expect(await scopeIdFor(KEY_A)).toBe(a);
    expect(await scopeIdFor(KEY_B)).not.toBe(a);
  });

  it('is 16 lowercase hex characters', async () => {
    expect(await scopeIdFor(KEY_A)).toMatch(/^[0-9a-f]{16}$/);
  });

  // The locked path reads base64 out of the keystore and decodes it; the unlocked path has the
  // bytes already. Same bytes must mean same id however they were carried.
  it('does not depend on how the bytes were carried', async () => {
    const copy = new Uint8Array(KEY_A); // a distinct object over a distinct buffer
    expect(await scopeIdFor(copy)).toBe(await scopeIdFor(KEY_A));
  });
});

describe('scopeIdOf', () => {
  it('round-trips a scope path', async () => {
    const id = await scopeIdFor(KEY_A);
    expect(scopeIdOf(`https://mail.example/${scopePathFor(id).slice(1)}`)).toBe(id);
  });

  // Every other registration on the origin — the app shell above all — must read as "not mine", or
  // the sweep would consider unregistering the worker serving the app offline.
  it('claims nothing that is not ours', () => {
    expect(scopeIdOf('https://mail.example/')).toBeNull();
    expect(scopeIdOf('https://mail.example/inbox')).toBeNull();
    expect(scopeIdOf('https://mail.example/push/')).toBeNull();
    expect(scopeIdOf('https://mail.example/push/not-hex-at-all/')).toBeNull();
    expect(scopeIdOf('https://mail.example/push/abc/')).toBeNull(); // too short to be an id
    expect(scopeIdOf('not a url')).toBeNull();
  });
});
