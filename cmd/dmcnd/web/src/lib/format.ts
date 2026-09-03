// The display formatters every screen used to carry its own copy of. One unit convention
// each, chosen once:
//
// formatBytes — an ACTUAL byte count (usage, an attachment, a backup file), in binary units
// with binary labels (KiB/MiB/GiB). The storage meter is a metered surface reporting against a
// ceiling that is provisioned in binary (a 5 GiB plan is 5 << 30 bytes), so it must never say the
// marketed "GB": a user near the cap would read a false over-limit. Attachments use the same
// function so the client has one notion of size.
//
// formatPlanQuota — the MARKETED figure of a plan ("5 GB", "500 MB"), i.e. what the pricing
// page says, derived from the plan's binary byte count. Only ever shown beside a plan name.

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || Number.isInteger(v) ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

export function formatPlanQuota(n: number): string {
  if (n >= 1024 * 1024 * 1024) return `${Math.round(n / (1024 * 1024 * 1024))} GB`;
  return `${Math.round(n / (1024 * 1024))} MB`;
}

// Dates. Messages carry unix seconds; the viewer's locale decides the rendering.

// formatDate: the full date of a message ("Tue, Sep 3, 2026").
export function formatDate(sec: number): string {
  return new Date(sec * 1000).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
}

// formatTime: the wall-clock time of a message ("9:41 AM").
export function formatTime(sec: number): string {
  return new Date(sec * 1000).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

// formatWhen: the compact list-row stamp — time today, "Sep 3" this year, "Sep 3, 25" before.
export function formatWhen(sec: number, now: Date = new Date()): string {
  const d = new Date(sec * 1000);
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  }
  const opts: Intl.DateTimeFormatOptions =
    d.getFullYear() === now.getFullYear()
      ? { month: 'short', day: 'numeric' }
      : { month: 'short', day: 'numeric', year: '2-digit' };
  return d.toLocaleDateString([], opts);
}

// formatLongDate: a calendar date spelled out ("September 3, 2026"), from an RFC 3339 string.
// Returns '' for an absent or unparseable value so the caller can omit the line entirely
// rather than show "Invalid Date".
export function formatLongDate(rfc3339: string): string {
  if (!rfc3339) return '';
  const d = new Date(rfc3339);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
}
