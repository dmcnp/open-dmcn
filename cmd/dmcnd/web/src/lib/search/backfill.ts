// Bringing the index level with the mailbox: fetch and index what it lacks, drop what has gone.
//
// A body can only be read the way the reader reads one, one message and two requests at a time,
// so the first pass over a large mailbox is long and the whole design is about making it
// resumable and polite: newest first, so the mail people search most becomes searchable first;
// two at a time; only while the page is in front of someone and online; written out every few
// hundred messages, so a closed tab loses at most that much work; and restarted from the manifest,
// never from the beginning. After that first pass, each new message costs one fetch.

export interface Candidate {
  hash: string;
  sentAt: number;
  /** From a sender the owner has blocked: never indexed, and dropped if it already was. */
  blocked: boolean;
}

/**
 * What one pass does. `fetch` is every unblocked candidate not yet indexed, newest first.
 * `remove` is every indexed message that is no longer a candidate, or whose sender is now blocked;
 * it is only worked out when the candidate list is known to be complete (`indexed` is passed), or
 * a mailbox that has not finished loading would read as a mailbox that was emptied.
 */
export function planPass(
  candidates: Candidate[],
  has: (hash: string) => boolean,
  indexed?: Iterable<string>,
): { fetch: string[]; remove: string[] } {
  const keep = new Set<string>();
  const fetch: Candidate[] = [];
  for (const c of candidates) {
    if (c.blocked) continue;
    keep.add(c.hash);
    if (!has(c.hash)) fetch.push(c);
  }
  fetch.sort((a, b) => b.sentAt - a.sentAt);
  const remove: string[] = [];
  if (indexed) for (const h of indexed) if (!keep.has(h)) remove.push(h);
  return { fetch: fetch.map(c => c.hash), remove };
}

/** The part of SearchIndex a backfill drives. */
export interface IndexLike {
  has(hash: string): boolean;
  hashes(): Iterable<string>;
  add(hash: string, text: string, filenames?: string[]): Promise<void>;
  remove(hashes: Iterable<string>): Promise<void>;
  flush(): Promise<void>;
  readonly pending: boolean;
  readonly wantsCompaction: boolean;
  compact(): Promise<void>;
}

export interface BackfillDeps {
  index: IndexLike;
  /** A message's text and the names of the attachments its sender attached. */
  fetch: (hash: string) => Promise<{ text: string; filenames: string[] }>;
  /** Whether fetching is appropriate right now (visible, online, the mailbox readable). */
  runnable: () => boolean;
  /** After each message indexed, and after each write. */
  onProgress: (flushed: boolean) => void;
  /** Called with a retry delay when a pass gave up on repeated failures. */
  retryLater?: (ms: number) => void;
  now?: () => number;
}

export const CONCURRENCY = 2;
export const FLUSH_EVERY = 200;
export const FLUSH_AFTER_MS = 20_000;
/** A message that failed this often is left for the next session rather than retried forever. */
export const MAX_FAILURES = 3;
/** This many failures in a row ends the pass: the network or the relay is having a bad minute. */
export const FAILURE_STREAK = 5;
export const RETRY_AFTER_MS = 60_000;

export class Backfiller {
  private candidates: Candidate[] = [];
  private complete = false;
  private running = false;
  private kicked = false;
  private stopped = false;
  private failures = new Map<string, number>();
  private idle: Promise<void> = Promise.resolve();
  private readonly now: () => number;

  constructor(private readonly deps: BackfillDeps) {
    this.now = deps.now ?? Date.now;
  }

  /**
   * The current candidates. `complete` says the lists they came from have loaded in full, which is
   * what allows a pass to remove anything.
   */
  update(candidates: Candidate[], complete: boolean): void {
    this.candidates = candidates;
    this.complete = complete;
    this.kick();
  }

  /** Start a pass, or have the running one re-plan as soon as its in-flight fetches land. */
  kick(): void {
    if (this.stopped) return;
    if (this.running) { this.kicked = true; return; }
    this.running = true;
    this.idle = this.loop().finally(() => { this.running = false; });
  }

  /** Stop after the fetches in flight; resolves once everything added has been written. */
  async stop(): Promise<void> {
    this.stopped = true;
    await this.idle;
    await this.deps.index.flush().catch(() => undefined);
  }

  /** Resolves when no pass is running (tests). */
  settled(): Promise<void> { return this.idle; }

  private async loop(): Promise<void> {
    do {
      this.kicked = false;
      try {
        await this.pass();
      } catch (err) {
        console.warn('search index: pass failed', err);
        return;
      }
    } while (this.kicked && !this.stopped);
  }

  private async pass(): Promise<void> {
    const { index } = this.deps;
    const plan = planPass(this.candidates, h => index.has(h), this.complete ? [...index.hashes()] : undefined);
    if (plan.remove.length) await index.remove(plan.remove);
    const queue = plan.fetch.filter(h => (this.failures.get(h) ?? 0) < MAX_FAILURES);

    let sinceFlush = 0;
    let lastFlush = this.now();
    let streak = 0;
    let gaveUp = false;
    const flush = async () => {
      sinceFlush = 0;
      lastFlush = this.now();
      await index.flush();
      this.deps.onProgress(true);
    };
    const go = () => !this.stopped && !this.kicked && !gaveUp && this.deps.runnable();

    const worker = async () => {
      while (queue.length && go()) {
        const hash = queue.shift()!;
        try {
          const { text, filenames } = await this.deps.fetch(hash);
          await index.add(hash, text, filenames);
          streak = 0;
          sinceFlush++;
          this.deps.onProgress(false);
        } catch (err) {
          this.failures.set(hash, (this.failures.get(hash) ?? 0) + 1);
          if (++streak >= FAILURE_STREAK) gaveUp = true;
          console.warn('search index: could not index a message', hash, err);
        }
        if (sinceFlush >= FLUSH_EVERY || (sinceFlush > 0 && this.now() - lastFlush >= FLUSH_AFTER_MS)) await flush();
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));

    if (index.pending) await flush();
    if (gaveUp) { this.deps.retryLater?.(RETRY_AFTER_MS); return; }
    if (!this.stopped && !this.kicked && index.wantsCompaction && this.deps.runnable()) await index.compact();
  }
}
