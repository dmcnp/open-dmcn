import { describe, expect, it } from 'vitest';
import { formatBytes, formatLongDate, formatPlanQuota, formatWhen } from './format';

describe('formatBytes', () => {
  it('uses binary units with binary labels', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1023)).toBe('1023 B');
    expect(formatBytes(1024)).toBe('1 KiB');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(8.2 * 1024 * 1024)).toBe('8.2 MiB');
    expect(formatBytes(3.8 * 1024 * 1024 * 1024)).toBe('3.8 GiB');
    expect(formatBytes(150 * 1024 * 1024)).toBe('150 MiB');
  });
});

describe('formatPlanQuota', () => {
  it('renders the marketed figure of a binary-provisioned plan', () => {
    expect(formatPlanQuota(5 * 1024 * 1024 * 1024)).toBe('5 GB');
    expect(formatPlanQuota(500 * 1024 * 1024)).toBe('500 MB');
  });
});

describe('formatWhen', () => {
  const now = new Date(2026, 8, 3, 12, 0, 0);
  it('shows a time for today, a month-day this year, and a short year before', () => {
    expect(formatWhen(new Date(2026, 8, 3, 9, 41).getTime() / 1000, now)).toMatch(/9:41/);
    expect(formatWhen(new Date(2026, 1, 14).getTime() / 1000, now)).toMatch(/Feb/);
    expect(formatWhen(new Date(2026, 1, 14).getTime() / 1000, now)).not.toMatch(/26/);
    expect(formatWhen(new Date(2025, 1, 14).getTime() / 1000, now)).toMatch(/25/);
  });
});

describe('formatLongDate', () => {
  it('spells the date out and is empty for a missing or malformed value', () => {
    expect(formatLongDate('2026-09-03T00:00:00Z')).toMatch(/2026/);
    expect(formatLongDate('')).toBe('');
    expect(formatLongDate('not a date')).toBe('');
  });
});
