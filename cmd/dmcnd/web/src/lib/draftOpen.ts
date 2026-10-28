// Whether an unsent message is open, readable from outside the shell that owns it, and a way to
// put it away first.
//
// Switching accounts closes the composer — AppLayout drops the compose state on the way through.
// The message itself is kept: the composer saves it as a draft before it goes (putAwayDraft). Only
// when that save reaches nowhere it would survive does a switch still cost the message, and then the
// account switcher asks first. A tapped notification can ask for the same switch, and it arrives at
// PushIntentRouter, which sits ABOVE the routes and so cannot see the shell's state. This is the
// narrowest thing that closes that gap: one boolean, a way to be told when it changes, and the open
// composer's own way to save and close.
//
// Not a context, deliberately. A provider would put every consumer of the compose state above the
// router, and the router needs to run on screens where the shell does not exist at all.

let open = false;
const listeners = new Set<() => void>();
let putAway: (() => Promise<boolean>) | null = null;

export function isDraftOpen(): boolean {
  return open;
}

export function setDraftOpen(next: boolean): void {
  if (open === next) return;
  open = next;
  for (const listener of listeners) listener();
}

/** Subscribe to changes. Returns the unsubscribe. */
export function onDraftOpenChange(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** The open composer registers how it saves and closes itself; null when it goes. */
export function setDraftPutAway(fn: (() => Promise<boolean>) | null): void {
  putAway = fn;
}

/**
 * Save the open message as a draft and close the composer. Resolves true when nothing is open or
 * the message was kept (on the relay, or on this device until it can reach it), false when it could
 * not be kept — the composer then stays open, and losing it is the person's call.
 */
export function putAwayDraft(): Promise<boolean> {
  return putAway ? putAway() : Promise.resolve(true);
}
