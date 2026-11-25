import { describe, expect, it } from 'vitest';
import { orderDevices, type OrderedDevice } from './devices';

const row = (pub: string, standing: OrderedDevice['standing'], enrolled: number, extra: Partial<OrderedDevice> = {}, retired?: number): OrderedDevice => ({
  record: { public: pub, enrolled_at: enrolled, ...(retired ? { retired_at: retired } : {}) },
  standing,
  mine: false,
  ...extra,
});

describe('orderDevices', () => {
  it('puts this browser first, a device asking to join next, then the rest newest first, removed last', () => {
    const ordered = orderDevices([
      row('old', 'active', 100),
      row('gone-early', 'removed', 50, {}, 150),
      row('stranger', 'waiting', 400),
      row('new', 'active', 300),
      row('me', 'active', 200, { mine: true }),
      row('gone-late', 'removed', 60, {}, 250),
    ]);
    expect(ordered.map(r => r.record.public)).toEqual(['me', 'stranger', 'new', 'old', 'gone-late', 'gone-early']);
  });

  it('does not lift a removed key of this browser above the live devices', () => {
    // A browser that was removed and paired again holds a new key; its old one is just history.
    const ordered = orderDevices([row('old-me', 'removed', 10, { mine: true }, 20), row('phone', 'active', 5)]);
    expect(ordered.map(r => r.record.public)).toEqual(['phone', 'old-me']);
  });
});
