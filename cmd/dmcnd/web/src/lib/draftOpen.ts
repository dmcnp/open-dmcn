// Whether an unsent message is open, readable from outside the shell that owns it.
//
// Switching accounts discards a draft — AppLayout drops the compose state on the way through, which
// is why the account switcher confirms first (AccountMenu's draftOpen). A tapped notification can
// ask for the same switch, and it arrives at PushIntentRouter, which sits ABOVE the routes and so
// cannot see the shell's state. This is the narrowest thing that closes that gap: one boolean and a
// way to be told when it changes.
//
// Not a context, deliberately. A provider would put every consumer of the compose state above the
// router, and the router needs to run on screens where the shell does not exist at all.

let open = false;
const listeners = new Set<() => void>();

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
