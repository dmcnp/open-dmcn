// How the device list in Privacy & security is ordered. Kept apart from the panel so it can be
// tested without a DOM.

import type { DeviceRecord, DeviceStanding } from './api/deviceRegistry';

export interface OrderedDevice {
  record: DeviceRecord;
  standing: DeviceStanding;
  mine: boolean;
}

const RANK: Record<DeviceStanding, number> = { waiting: 1, active: 2, removed: 3 };

/**
 * This browser first, so the owner can find their bearings; then any device asking to join
 * without approval, because that is the one that needs an answer; then the rest, newest first,
 * with removed devices last, most recently removed first.
 */
export function orderDevices<T extends OrderedDevice>(rows: T[]): T[] {
  const rank = (r: T) => (r.mine && r.standing !== 'removed' ? 0 : RANK[r.standing]);
  const when = (r: T) => (r.standing === 'removed' ? r.record.retired_at ?? 0 : r.record.enrolled_at);
  return [...rows].sort((a, b) => rank(a) - rank(b) || when(b) - when(a) || a.record.public.localeCompare(b.record.public));
}
