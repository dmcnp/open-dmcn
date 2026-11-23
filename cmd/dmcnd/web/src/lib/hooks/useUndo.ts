import { createContext, useContext, useState, useCallback, useRef, ReactNode, createElement } from 'react';
import { UndoBar } from '../../components/UndoBar';

// useUndo: after a move, a delete or an archive, a short bar says what happened, with Undo. A
// full swipe on the phone is easy to do by accident, and a moved message vanishes from the list
// it was in, so the way back is offered where the hand already is rather than in another view.
//
// One notice at a time: a new action replaces the bar (its own Undo is the one wanted next). The
// bar goes after a few seconds; what it undoes is the caller's, so this only holds and runs it.

export interface UndoNotice {
  id: number;
  text: string;
  undo: () => void | Promise<void>;
}

interface UndoContextValue {
  /** Shows the bar. `undo` runs at most once, when Undo is pressed. */
  offerUndo: (text: string, undo: () => void | Promise<void>) => void;
}

const UndoContext = createContext<UndoContextValue | null>(null);

/** How long the bar stays, in ms. Long enough to read and reach; the Apple client's is similar. */
export const UNDO_MS = 6000;

export function UndoProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<UndoNotice | null>(null);
  const nextId = useRef(1);

  const offerUndo = useCallback((text: string, undo: () => void | Promise<void>) => {
    setNotice({ id: nextId.current++, text, undo });
  }, []);

  const dismiss = useCallback((id: number) => {
    setNotice(n => (n?.id === id ? null : n));
  }, []);

  const runUndo = useCallback((n: UndoNotice) => {
    dismiss(n.id);
    void Promise.resolve().then(n.undo).catch(() => { /* the next sync shows where things are */ });
  }, [dismiss]);

  return createElement(
    UndoContext.Provider,
    { value: { offerUndo } },
    children,
    notice ? createElement(UndoBar, { key: notice.id, notice, onUndo: runUndo, onDismiss: dismiss, timeoutMs: UNDO_MS }) : null,
  );
}

export function useUndo(): UndoContextValue {
  const ctx = useContext(UndoContext);
  if (!ctx) throw new Error('useUndo must be used within UndoProvider');
  return ctx;
}
