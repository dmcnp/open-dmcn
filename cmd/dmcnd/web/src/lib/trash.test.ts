import { describe, expect, it } from 'vitest';
import { expiredTrash, purgeAt, purgeWhen, trashDays, TRASH_DAYS_DEFAULT } from './trash';
import type { FlagRecord } from './api/flagStore';

const DAY = 24 * 60 * 60 * 1000;
const flag = (trashedAt?: number): FlagRecord => ({ v: 1, trashedAt, updatedAt: 0, deviceId: '' });

describe('trashDays', () => {
  it('defaults to seven days for an account that never chose', () => {
    expect(trashDays(undefined)).toBe(TRASH_DAYS_DEFAULT);
    expect(TRASH_DAYS_DEFAULT).toBe(7);
  });
  it('keeps a choice within one to seven whole days', () => {
    expect(trashDays(3)).toBe(3);
    expect(trashDays(0)).toBe(1);
    expect(trashDays(30)).toBe(7);
    expect(trashDays(2.6)).toBe(3);
    expect(trashDays(Number.NaN)).toBe(TRASH_DAYS_DEFAULT);
  });
});

describe('expiredTrash', () => {
  const now = Date.UTC(2026, 9, 29, 12);
  const flags = new Map<string, FlagRecord>([
    ['kept', flag()],
    ['fresh', flag(now - 2 * DAY)],
    ['due', flag(now - 7 * DAY)],
    ['overdue', flag(now - 30 * DAY)],
  ]);

  it('returns only deleted mail whose time is up', () => {
    expect(expiredTrash(flags, 7, now).sort()).toEqual(['due', 'overdue']);
  });
  it('applies a shorter retention to mail already waiting', () => {
    expect(expiredTrash(flags, 1, now).sort()).toEqual(['due', 'fresh', 'overdue']);
  });
  it('never touches mail that was not deleted', () => {
    expect(expiredTrash(flags, 1, now + 365 * DAY)).not.toContain('kept');
  });
});

describe('purgeWhen', () => {
  const at = new Date(2026, 9, 29, 9).getTime();
  it('counts calendar days to the removal', () => {
    expect(purgeWhen(at, 7, at)).toBe('in 7 days');
    expect(purgeWhen(at, 1, at)).toBe('tomorrow');
    expect(purgeWhen(at, 1, purgeAt(at, 1) - 60_000)).toBe('today');
    expect(purgeWhen(at, 1, purgeAt(at, 1) + DAY)).toBe('today');
  });
});
