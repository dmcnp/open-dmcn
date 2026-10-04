// Whether a mailbox has never had mail in either direction: the condition for landing on Getting
// started (deployment.gettingStarted) and for the Inbox pointing there instead of saying there is
// nothing to read.
//
// A new address opens to an empty inbox, and "You're all caught up" is true but useless on a first
// visit: the cohort read on 4 October 2026 found twelve of fourteen new accounts never came back
// after it. An account that has never received or sent anything is the one moment the inbox has
// nothing better to show than how to start.

export interface FirstRunInput {
  // Both listings have landed. Before then an empty list says nothing about the mailbox.
  mailLoaded: boolean;
  sentLoaded: boolean;
  // Received mail, control messages excluded, and the Sent store.
  mailCount: number;
  sentCount: number;
  // Something else already explains the empty list: reading locked, an address awaiting
  // approval, a browser that is not an enrolled device, or a listing error.
  explained: boolean;
}

export function isFirstRun(s: FirstRunInput): boolean {
  return s.mailLoaded && s.sentLoaded && !s.explained && s.mailCount === 0 && s.sentCount === 0;
}
