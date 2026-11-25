import { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode, createElement } from 'react';
import { UndoBar } from '../../components/UndoBar';
import { useAuth } from './useAuth';
import { useKeys } from './useKeys';
import { UndoFailedError } from '../filingActions';

// useUndo: after a move, a delete or an archive, a short bar says what happened, with Undo. A
// full swipe on the phone is easy to do by accident, and a moved message vanishes from the list
// it was in, so the way back is offered where the hand already is rather than in another view.
// The same bar says so when an action fails, without an Undo.
//
// One notice at a time: a new one replaces the bar. The bar goes after a few seconds, and at once
// when the account changes (switching, locking, signing out): an Undo for one mailbox must never
// be pressed in another. What it undoes is the caller's; this only holds it and runs it once.

export interface UndoNotice {
  id: number;
  text: string;
  undo?: () => void | Promise<void>;
}

interface UndoContextValue {
  /** Shows the bar. With `undo`, it has an Undo button, which runs `undo` at most once. */
  offerUndo: (text: string, undo?: () => void | Promise<void>) => void;
}

const UndoContext = createContext<UndoContextValue | null>(null);

/** How long the bar stays, in ms. Long enough to read and reach; the Apple client's is similar. */
export const UNDO_MS = 6000;

export function UndoProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<UndoNotice | null>(null);
  const nextId = useRef(1);
  const { address } = useAuth();
  const { keys } = useKeys();

  // A different account, or none (switched, locked, signed out): whatever the bar offered belongs
  // to the one before. Not the session token, which renews for the same account.
  useEffect(() => { setNotice(null); }, [address, keys]);

  const offerUndo = useCallback((text: string, undo?: () => void | Promise<void>) => {
    setNotice({ id: nextId.current++, text, undo });
  }, []);

  const dismiss = useCallback((id: number) => {
    setNotice(n => (n?.id === id ? null : n));
  }, []);

  const runUndo = useCallback((n: UndoNotice) => {
    dismiss(n.id);
    if (!n.undo) return;
    void Promise.resolve().then(n.undo).catch(e => {
      const text = e instanceof UndoFailedError ? e.message : "Couldn't undo. Check your connection and try again.";
      setNotice({ id: nextId.current++, text });
    });
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
