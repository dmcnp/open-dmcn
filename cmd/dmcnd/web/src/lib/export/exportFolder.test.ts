import { describe, expect, it } from 'vitest';
import { ATTEMPTS, ExportStalled, FAILURE_STREAK, WINDOW, exportFolder } from './exportFolder';

const enc = new TextEncoder();
const dec = new TextDecoder();
const noSleep = async () => {};

// Loads resolve when the test says so, in any order, so the driver's ordering is what is tested.
function gated() {
  const waiting = new Map<number, () => void>();
  const started: number[] = [];
  // Each message renders as two chunks, so the driver's writing of chunks in order is tested too.
  const load = (i: number) => new Promise<() => Uint8Array[]>(resolve => {
    started.push(i);
    waiting.set(i, () => resolve(() => [enc.encode(`m${i}`), enc.encode(';')]));
  });
  const release = async (i: number) => { waiting.get(i)!(); await new Promise(r => setTimeout(r, 0)); };
  return { load, started, release };
}

describe('exportFolder', () => {
  it('writes in order whatever order the loads finish in, and loads only a window ahead', async () => {
    const g = gated();
    const written: string[] = [];
    const progress: number[] = [];
    const run = exportFolder({
      items: [0, 1, 2, 3, 4], load: g.load, sleep: noSleep,
      write: async b => { written.push(dec.decode(b)); },
      onProgress: done => progress.push(done),
    });
    await new Promise(r => setTimeout(r, 0));
    expect(WINDOW).toBe(2);
    expect(g.started).toEqual([0, 1]);
    await g.release(1);
    expect(written).toEqual([]);
    await g.release(0);
    expect(written.join('')).toBe('m0;m1;');
    expect(g.started).toEqual([0, 1, 2, 3]);
    await g.release(3);
    await g.release(2);
    await g.release(4);
    const res = await run;
    expect(written.join('')).toBe('m0;m1;m2;m3;m4;');
    expect(progress).toEqual([1, 2, 3, 4, 5]);
    expect(res).toEqual({ written: 5, bytes: 15, skipped: [] });
  });

  it('retries a message, then leaves it out and carries on', async () => {
    const tries = new Map<string, number>();
    const written: string[] = [];
    const res = await exportFolder({
      items: ['ok', 'flaky', 'bad', 'ok2'], sleep: noSleep,
      load: async id => {
        const n = (tries.get(id) ?? 0) + 1;
        tries.set(id, n);
        if (id === 'bad' || (id === 'flaky' && n === 1)) throw new Error(`no ${id}`);
        return () => [enc.encode(id)];
      },
      write: async b => { written.push(dec.decode(b)); },
    });
    expect(written).toEqual(['ok', 'flaky', 'ok2']);
    expect(res.skipped).toEqual(['bad']);
    expect(tries.get('bad')).toBe(ATTEMPTS);
    expect(tries.get('flaky')).toBe(2);
  });

  it('stops when several messages in a row will not load', async () => {
    const items = Array.from({ length: FAILURE_STREAK + 3 }, (_, i) => i);
    const run = exportFolder({ items, sleep: noSleep, load: async () => { throw new Error('offline'); }, write: async () => {} });
    await expect(run).rejects.toBeInstanceOf(ExportStalled);
  });

  it('stops on cancel without writing anything more', async () => {
    const g = gated();
    const abort = new AbortController();
    const written: string[] = [];
    const run = exportFolder({ items: [0, 1, 2], load: g.load, sleep: noSleep, signal: abort.signal, write: async b => { written.push(dec.decode(b)); } });
    await new Promise(r => setTimeout(r, 0));
    const stopped = expect(run).rejects.toMatchObject({ name: 'AbortError' });
    await g.release(0);
    abort.abort();
    await g.release(1);
    await stopped;
    expect(written.join('')).toBe('m0;');
  });

  it('renders each message only when its turn to be written comes, in order', async () => {
    // A bridged parent records its real Message-ID as it is written; a reply opened alongside it
    // must not be rendered before that, or it would name the parent wrongly. So the second
    // message is opened FIRST here, and must still render only after the first is written.
    const events: string[] = [];
    const waiting = new Map<number, () => void>();
    const run = exportFolder({
      items: [0, 1], sleep: noSleep,
      load: i => new Promise(resolve => waiting.set(i, () => resolve(() => { events.push(`render ${i}`); return [enc.encode(String(i))]; }))),
      write: async b => { events.push(`write ${dec.decode(b)}`); },
    });
    await new Promise(r => setTimeout(r, 0));
    waiting.get(1)!();
    await new Promise(r => setTimeout(r, 0));
    expect(events).toEqual([]);
    waiting.get(0)!();
    await run;
    expect(events).toEqual(['render 0', 'write 0', 'render 1', 'write 1']);
  });

  it('writes an empty folder as nothing', async () => {
    expect(await exportFolder({ items: [], load: async () => () => [], write: async () => {} })).toEqual({ written: 0, bytes: 0, skipped: [] });
  });
});
