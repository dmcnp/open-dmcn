import { describe, expect, it } from 'vitest';
import { bufferSource, fromHex, randomHex, toHex } from './bytes';

describe('hex', () => {
  it('round-trips and zero-pads', () => {
    const b = new Uint8Array([0, 1, 15, 16, 255]);
    expect(toHex(b)).toBe('00010f10ff');
    expect(fromHex('00010f10ff')).toEqual(b);
    expect(toHex(new Uint8Array())).toBe('');
  });
  it('randomHex is 2n lowercase hex characters', () => {
    expect(randomHex(16)).toMatch(/^[0-9a-f]{32}$/);
    expect(randomHex(8)).not.toBe(randomHex(8));
  });
});

describe('bufferSource', () => {
  it('returns the same view when the buffer is an ArrayBuffer and copies otherwise', () => {
    const plain = new Uint8Array([1, 2, 3]);
    expect(bufferSource(plain)).toBe(plain);
    const shared = new Uint8Array(new SharedArrayBuffer(3));
    shared.set([4, 5, 6]);
    const copy = bufferSource(shared);
    expect(copy).not.toBe(shared);
    expect(Array.from(copy)).toEqual([4, 5, 6]);
    expect(copy.buffer instanceof ArrayBuffer).toBe(true);
  });
});
