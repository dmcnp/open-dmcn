import { describe, expect, it } from 'vitest';
import type { FlagDelta, FlagRecord } from './api/flagStore';
import {
  moveAlwaysWithUndo, moveWithUndo, setArchivedWithUndo, trashWithUndo, UndoFailedError, type ActionDeps,
} from './filingActions';

// A fake flag store: records per message, writes that can be made to fail, and the bar's notices.
function fake(initial: Record<string, Partial<FlagRecord>> = {}) {
  const flags = new Map<string, FlagRecord>(
    Object.entries(initial).map(([h, f]) => [h, { v: 1, updatedAt: 0, deviceId: '', ...f }]),
  );
  const failing = new Set<string>();
  const notices: { text: string; undo?: () => Promise<void> }[] = [];
  let account: string | null = 'me@x';
  const deps: ActionDeps = {
    setFlag: async (h: string, delta: FlagDelta) => {
      if (failing.has(h)) throw new Error('offline');
      flags.set(h, { ...(flags.get(h) ?? { v: 1, updatedAt: 0, deviceId: '' }), ...delta });
    },
    flagOf: h => flags.get(h),
    notify: (text, undo) => { notices.push({ text, undo }); },
    account: () => account,
  };
  return {
    deps, flags, failing, notices,
    last: () => notices[notices.length - 1],
    switchAccount: (a: string | null) => { account = a; },
  };
}

describe('moveWithUndo', () => {
  it('moves, says where, and Undo puts folder and archive back', async () => {
    const f = fake({ a: { folderId: 'old', archived: true } });
    await moveWithUndo(f.deps, ['a', 'b'], 'f1', 'Projects');
    expect(f.flags.get('a')?.folderId).toBe('f1');
    expect(f.flags.get('b')?.folderId).toBe('f1');
    expect(f.last().text).toBe('Moved 2 messages to Projects');
    await f.last().undo!();
    expect(f.flags.get('a')).toMatchObject({ folderId: 'old', archived: true });
    expect(f.flags.get('b')?.folderId).toBeUndefined();
  });

  it('says so, with no Undo, when nothing could be moved', async () => {
    const f = fake();
    f.failing.add('a');
    const r = await moveWithUndo(f.deps, ['a'], 'f1', 'Projects');
    expect(r.done).toEqual([]);
    expect(f.last().text).toBe("Couldn't move this message. Check your connection and try again.");
    expect(f.last().undo).toBeUndefined();
  });

  it('counts a partial move, and Undo only touches what moved', async () => {
    const f = fake({ b: { folderId: 'keep' } });
    f.failing.add('b');
    await moveWithUndo(f.deps, ['a', 'b'], 'f1', 'Projects');
    expect(f.last().text).toBe("Moved 1 of 2 messages to Projects. The rest couldn't be moved.");
    f.failing.clear();
    await f.last().undo!();
    expect(f.flags.get('b')?.folderId).toBe('keep');
  });

  it('does nothing on Undo once the account has changed', async () => {
    const f = fake();
    await moveWithUndo(f.deps, ['a'], 'f1', 'Projects');
    f.switchAccount('other@x');
    await f.last().undo!();
    expect(f.flags.get('a')?.folderId).toBe('f1');
  });

  it('reports an Undo whose writes fail', async () => {
    const f = fake();
    await moveWithUndo(f.deps, ['a'], 'f1', 'Projects');
    f.failing.add('a');
    await expect(f.last().undo!()).rejects.toBeInstanceOf(UndoFailedError);
  });
});

describe('trash and archive', () => {
  it('Undo of a delete clears the deleted mark again', async () => {
    const f = fake();
    await trashWithUndo(f.deps, ['a'], 123);
    expect(f.flags.get('a')?.trashedAt).toBe(123);
    expect(f.last().text).toBe('Moved to Deleted');
    await f.last().undo!();
    expect(f.flags.get('a')?.trashedAt).toBeUndefined();
  });

  it('a failed delete says so instead of "Moved to Deleted"', async () => {
    const f = fake();
    f.failing.add('a');
    await trashWithUndo(f.deps, ['a'], 1);
    expect(f.last().text).toBe("Couldn't delete this message. Check your connection and try again.");
  });

  it('Undo of an archive puts the mark back as it was', async () => {
    const f = fake();
    await setArchivedWithUndo(f.deps, ['a'], true);
    expect(f.last().text).toBe('Archived');
    await f.last().undo!();
    expect(f.flags.get('a')?.archived).toBeUndefined();
  });
});

describe('moveAlwaysWithUndo', () => {
  it('saves the rule only after something moved', async () => {
    const f = fake();
    f.failing.add('a');
    let saved = false;
    await moveAlwaysWithUndo(f.deps, ['a'], 'f1', 'Projects', async () => { saved = true; }, async () => {});
    expect(saved).toBe(false);
  });

  it('an Undo pressed before the rule is saved waits for the save, then restores', async () => {
    const f = fake();
    const order: string[] = [];
    let finishSave!: () => void;
    const saving = new Promise<void>(r => { finishSave = r; });
    const running = moveAlwaysWithUndo(f.deps, ['a'], 'f1', 'Projects',
      async () => { await saving; order.push('saved'); },
      async () => { order.push('restored'); });
    // Let the move finish and the bar appear, while the save is still in flight.
    await new Promise(r => setTimeout(r, 0));
    const undo = f.last().undo!();
    await new Promise(r => setTimeout(r, 0));
    expect(order).toEqual([]);
    finishSave();
    await undo;
    await running;
    expect(order).toEqual(['saved', 'restored']);
    expect(f.flags.get('a')?.folderId).toBeUndefined();
  });

  it('keeps the move and its Undo when the rule fails to save, and says so', async () => {
    const f = fake();
    await moveAlwaysWithUndo(f.deps, ['a'], 'f1', 'Projects', async () => { throw new Error('offline'); }, async () => {});
    expect(f.flags.get('a')?.folderId).toBe('f1');
    expect(f.last().text).toContain("the rule couldn't be saved");
    expect(f.last().undo).toBeDefined();
  });
});
