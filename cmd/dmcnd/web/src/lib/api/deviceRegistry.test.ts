import { describe, it, expect } from 'vitest';
import { classifyEnrolment } from './deviceRegistry';

// Putting this browser on the registry doubles as the probe for whether it is already there, and
// it has to: knowing would mean listing the registry, and listing is itself gated on being
// enrolled. So the relay's answer to "let me in" is what distinguishes the states.
//
// Getting this classification wrong is quiet and bad in both directions. Read "already enrolled"
// as a failure and every app open shows a device that cannot get in; read "needs approval" as
// success and a browser that is shut out believes it is fine until the first mailbox call fails.
describe('classifyEnrolment', () => {
  it('treats an existing enrolment as success, not an error', () => {
    // Verbatim what the browser sees: the relay's refusal, wrapped by the mailbox proxy.
    const err = new Error(
      'device enrol failed: relay: mailbox-ext: INVALID_REQUEST: this device is already enrolled',
    );
    expect(classifyEnrolment(err)).toEqual({ state: 'enrolled', genesis: false });
  });

  it('recognises a claimed registry as needing approval rather than as an outage', () => {
    // Verbatim relay.ErrDeviceApprovalRequired, wrapped by the mailbox proxy. Note it also
    // contains the word "already": matching loosely on that would read this as "enrolled", which
    // is the exact mis-read this test exists to prevent.
    const err = new Error(
      'device enrol failed: relay: enrolment needs approval from a device already on this mailbox',
    );
    expect(classifyEnrolment(err)).toEqual({ state: 'needs-approval' });
  });

  it('leaves anything else as unavailable, so a bad minute of network is not a verdict', () => {
    // An unreachable fleet says nothing about whether this device belongs; the next open asks
    // again. Mistaking it for "shut out" would send someone to re-pair a device that was fine.
    const err = new Error('fetch failed');
    expect(classifyEnrolment(err)).toEqual({ state: 'unavailable', error: err });
  });

  it('does not mistake a non-Error rejection for a state', () => {
    expect(classifyEnrolment('something threw a string')).toMatchObject({ state: 'unavailable' });
  });
});
