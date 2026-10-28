// When the composer saves: a little after typing stops, and never less often than every so often
// while it does not.
//
// Waiting for a pause keeps a sentence from turning into a save per keystroke — on the relay every
// save is a signed challenge and two writes. The ceiling keeps someone who types for a minute
// without stopping from having a minute to lose. Saves never overlap: a change that arrives while
// one is in flight is picked up by the next, and flush() resolves only once what was pending when
// it was called is saved.

export interface Timers {
  set(fn: () => void, ms: number): unknown;
  clear(handle: unknown): void;
  now(): number;
}

const browserTimers: Timers = {
  set: (fn, ms) => window.setTimeout(fn, ms),
  clear: handle => window.clearTimeout(handle as number),
  now: () => Date.now(),
};

export class SaveScheduler {
  private timer: unknown;
  private hasTimer = false;
  // When the oldest unsaved change was made; undefined while everything is saved.
  private dirtySince: number | undefined;
  private running: Promise<void> | undefined;
  private disposed = false;

  /**
   * `run` saves the current state and throws only when it is worth trying again (the network); a
   * failed save stays pending and is retried after `maxWaitMs`.
   */
  constructor(
    private readonly run: () => Promise<void>,
    private readonly quietMs: number,
    private readonly maxWaitMs: number,
    private readonly timers: Timers = browserTimers,
  ) {}

  /** Something changed. */
  touch(): void {
    if (this.disposed) return;
    const now = this.timers.now();
    this.dirtySince ??= now;
    this.schedule(Math.max(0, Math.min(this.quietMs, this.dirtySince + this.maxWaitMs - now)));
  }

  /** Whether a change is waiting to be saved. */
  get pending(): boolean {
    return this.dirtySince !== undefined;
  }

  /** Save now if anything is pending. Rejects if that save fails (it stays pending). */
  async flush(): Promise<void> {
    this.cancel();
    while (this.running) await this.running.catch(() => undefined);
    if (this.dirtySince === undefined) return;
    const since = this.dirtySince;
    this.dirtySince = undefined;
    this.running = this.run().finally(() => { this.running = undefined; });
    try {
      await this.running;
    } catch (err) {
      // Still unsaved, and still as old as it was.
      if (this.dirtySince === undefined || since < this.dirtySince) this.dirtySince = since;
      if (!this.disposed) this.schedule(this.maxWaitMs);
      throw err;
    }
  }

  /** Stop the timer for good; a flush() still runs. */
  dispose(): void {
    this.disposed = true;
    this.cancel();
  }

  /** Drop what is pending and wait out a save in flight: what it saves is about to be removed. */
  async abandon(): Promise<void> {
    this.dispose();
    this.dirtySince = undefined;
    while (this.running) await this.running.catch(() => undefined);
  }

  private schedule(ms: number): void {
    this.cancel();
    this.hasTimer = true;
    this.timer = this.timers.set(() => {
      this.hasTimer = false;
      this.flush().catch(() => undefined);
    }, ms);
  }

  private cancel(): void {
    if (!this.hasTimer) return;
    this.timers.clear(this.timer);
    this.hasTimer = false;
  }
}
