// Forwarding, as the composer honours it.
//
// An address's owner may sign a forward_to into its identity record (SPEC_CORE §1): another
// address, DMCN or ordinary email, that also gets its mail. A sender's client sends that address
// its own copy, sealed to it when it has a DMCN identity and as ordinary email otherwise, and says
// so before Send. One hop only: a forwarding address's own forward is never followed. These are the
// rules and the words; the dialog does the sending.

// What a forwarding address turned out to be when it was looked up: a DMCN identity (the copy is
// end-to-end encrypted), ordinary email (it is not), or not known yet.
export type ForwardTargetKind = 'dmcn' | 'email' | 'unknown';

export interface ForwardCopy {
  forAddr: string; // the recipient whose forward this is
  target: string;  // where the copy goes
}

// planForwardCopies decides which forward copies a message needs: one per distinct forwarding
// address, and none for an address that already gets the message (a recipient in its own right)
// or that is the sender. Only recipients' forwards are read, which is what keeps it to one hop.
export function planForwardCopies(
  forwards: { address: string; forwardTo?: string }[],
  recipients: string[],
  sender: string,
): ForwardCopy[] {
  const taken = new Set([...recipients, sender].map(a => a.trim().toLowerCase()));
  const out: ForwardCopy[] = [];
  for (const { address, forwardTo } of forwards) {
    const target = forwardTo?.trim();
    if (!target) continue;
    const key = target.toLowerCase();
    if (taken.has(key)) continue;
    taken.add(key);
    out.push({ forAddr: address, target });
  }
  return out;
}

// The notice shown before Send. It names the address, because the sender is the one deciding
// whether to send, and for ordinary email it says the copy is not end-to-end encrypted.
export function forwardNotice(addr: string, target: string, kind: ForwardTargetKind): string {
  switch (kind) {
    case 'dmcn':
      return `Mail to ${addr} also goes to ${target}. That copy is end-to-end encrypted too.`;
    case 'email':
      return `Mail to ${addr} also goes to ${target} as ordinary email, so that copy is not end-to-end encrypted.`;
    default:
      return `Mail to ${addr} also goes to ${target}.`;
  }
}

// The notice where the forwarding address is ordinary email and this deployment cannot send any
// (the reference daemon has no bridge path): the sender should know that copy will not go.
export function forwardUnsendableNotice(addr: string, target: string): string {
  return `Mail to ${addr} also goes to ${target} as ordinary email, which can't be sent from here, so ${target} won't get a copy.`;
}

// After sending: the recipient's account is closed, and the forward was the only copy.
export function forwardedOnlyMessage(addr: string, target: string): string {
  return `${addr} has closed their account. Your message went to their forwarding address, ${target}.`;
}

// After sending: the recipient got it, the forward copy did not go out.
export function forwardFailedMessage(addr: string, target: string): string {
  return `${addr} has your message, but the copy to their forwarding address, ${target}, could not be sent.`;
}

// After sending: the account is closed AND the forward failed, so this recipient got nothing.
export function forwardOnlyFailedMessage(addr: string, target: string): string {
  return `${addr} has closed their account, and the copy to their forwarding address, ${target}, could not be sent. They have not received your message.`;
}
