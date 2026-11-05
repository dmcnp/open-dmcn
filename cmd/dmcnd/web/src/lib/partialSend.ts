// A send that reached some recipients and not others.
//
// Every recipient is tried, so one failure doesn't stop the rest. What's left afterwards is a Sent
// copy listing who got it and a draft addressed to who didn't, so pressing Send again can't reach
// anyone twice. These are the rules and the words; the dialog does the sending.

export interface Undelivered {
  address: string;
  reason: string; // a sentence naming the address, to show as it stands
}

export interface Audience {
  to: string[];
  cc: string[];
  bcc: string[];
}

const same = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

// reachedAudience is who a Sent copy lists: everyone but the addresses that failed.
export function reachedAudience(all: Audience, undelivered: Undelivered[]): Audience {
  const reached = (list: string[]) => list.filter(a => !undelivered.some(u => same(u.address, a)));
  return { to: reached(all.to), cc: reached(all.cc), bcc: reached(all.bcc) };
}

// retryAudience is who the draft stays addressed to. A failed Cc moves up to To when To would
// otherwise be empty, since Cc was visible anyway. A failed Bcc never does: To would show them.
export function retryAudience(all: Audience, undelivered: Undelivered[]): Audience {
  const failed = (list: string[]) => list.filter(a => undelivered.some(u => same(u.address, a)));
  const to = failed(all.to);
  const cc = failed(all.cc);
  const bcc = failed(all.bcc);
  return to.length > 0 ? { to, cc, bcc } : { to: cc, cc: [], bcc };
}

// partialSendMessage says what happened and what Send does now.
export function partialSendMessage(delivered: string[], undelivered: Undelivered[]): string {
  const missed = undelivered.map(u => u.address).join(', ');
  const reasons = undelivered.map(u => u.reason).join(' ');
  return `This message reached ${delivered.join(', ')}. ${reasons} Press Send to try again. It will go only to ${missed}.`;
}
