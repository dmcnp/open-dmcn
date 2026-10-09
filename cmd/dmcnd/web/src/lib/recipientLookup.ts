// How the composer reads a recipient lookup that did not return an identity, and a delivery the
// recipient's relay refused because the account is closed. Its own module so the rules are
// testable without the dialog.
import { ApiError } from './api/bearer';

// 'legacy': the directory answered that there is no DMCN identity here, so the address is
// ordinary email. 'unchecked': the directory could not be asked (a 502, a timeout, a network
// fault). The two used to be one, so a passing outage painted every recipient as "legacy" and
// made a pinned contact look as if their identity had gone.
export type LookupFailureKind = 'legacy' | 'unchecked';

export function lookupFailureKind(err: unknown): LookupFailureKind {
  return err instanceof ApiError && err.status === 404 ? 'legacy' : 'unchecked';
}

// The relay refused the copy because the recipient's account is closed (the send answers 410).
export function isRecipientClosed(err: unknown): boolean {
  return err instanceof ApiError && err.status === 410;
}

export function recipientClosedMessage(addr: string): string {
  return `${addr} has closed their account, so your message was not delivered to them.`;
}
