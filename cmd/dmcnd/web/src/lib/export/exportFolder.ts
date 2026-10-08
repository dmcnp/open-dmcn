// Writing one folder out, message by message.
//
// A body can only be had the way the reader gets one: one message, one fetch and decrypt. So the
// export fetches a couple of messages ahead of the one it is writing and writes them strictly in
// order, oldest first, which is the order an mbox is read in. At most the window's worth of
// messages is in memory at any time, however large the folder, and each one is written in the
// chunks it was rendered in (an attachment's encoding is its own chunk).
//
// Unlike the search backfill (search/backfill.ts) it does not wait for the page to be in front of
// anyone: someone asked for this file and is waiting for it. A message that will not load is
// tried again a couple of times and then left out and counted, so one bad message never costs the
// whole file; several failing in a row means the network or the relay is down, and the export
// stops and says so rather than writing a file that is mostly gaps.

export const WINDOW = 2;
export const ATTEMPTS = 3;
export const FAILURE_STREAK = 5;
const RETRY_MS = 1000;

export interface ExportDeps<T> {
  /** The messages, in the order they go into the file. */
  items: T[];
  /**
   * Open one message, ahead of the one being written. Resolves to the function that renders it as
   * its mbox entry, in chunks; that is called only when its turn to be written comes, in order.
   */
  load: (item: T) => Promise<() => Uint8Array[]>;
  write: (bytes: Uint8Array) => Promise<void>;
  signal?: AbortSignal;
  /** After each message written or left out. */
  onProgress?: (done: number, total: number) => void;
  sleep?: (ms: number) => Promise<void>;
}

export interface ExportResult<T> {
  written: number;
  bytes: number;
  /** The messages left out after every attempt failed. */
  skipped: T[];
}

/** Thrown when FAILURE_STREAK messages in a row would not load. */
export class ExportStalled extends Error {
  constructor(cause: unknown) {
    super('several messages in a row could not be loaded', { cause });
    this.name = 'ExportStalled';
  }
}

const aborted = () => new DOMException('export cancelled', 'AbortError');

export async function exportFolder<T>(deps: ExportDeps<T>): Promise<ExportResult<T>> {
  const { items, signal } = deps;
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>(r => setTimeout(r, ms)));
  const result: ExportResult<T> = { written: 0, bytes: 0, skipped: [] };

  const loadWithRetry = async (item: T): Promise<() => Uint8Array[]> => {
    let lastErr: unknown;
    for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
      if (signal?.aborted) throw aborted();
      try {
        return await deps.load(item);
      } catch (err) {
        lastErr = err;
        if (attempt < ATTEMPTS) await sleep(RETRY_MS * attempt);
      }
    }
    throw lastErr;
  };

  // Each started load, settled into a value so an unawaited failure is never an unhandled one.
  type Settled = { ok: true; render: () => Uint8Array[] } | { ok: false; err: unknown };
  const started = new Map<number, Promise<Settled>>();
  const start = (i: number) => {
    if (i < items.length && !started.has(i)) {
      started.set(i, loadWithRetry(items[i]).then(render => ({ ok: true as const, render }), err => ({ ok: false as const, err })));
    }
  };

  let streak = 0;
  for (let i = 0; i < items.length; i++) {
    if (signal?.aborted) throw aborted();
    for (let j = i; j < i + WINDOW; j++) start(j);
    const got = await started.get(i)!;
    started.delete(i);
    if (signal?.aborted) throw aborted();
    if (got.ok) {
      for (const chunk of got.render()) {
        await deps.write(chunk);
        result.bytes += chunk.length;
      }
      result.written++;
      streak = 0;
    } else {
      result.skipped.push(items[i]);
      console.warn('export: left a message out after every attempt failed', got.err);
      if (++streak >= FAILURE_STREAK) throw new ExportStalled(got.err);
    }
    deps.onProgress?.(i + 1, items.length);
  }
  return result;
}
