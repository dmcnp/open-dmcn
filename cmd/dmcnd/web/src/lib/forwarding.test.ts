import { describe, expect, it } from 'vitest';
import {
  forwardFailedMessage, forwardNotice, forwardOnlyFailedMessage, forwardUnsendableNotice, forwardedOnlyMessage, planForwardCopies,
} from './forwarding';

describe('planForwardCopies', () => {
  it('sends one copy per forwarding address', () => {
    expect(planForwardCopies(
      [{ address: 'alice@dmcn.email', forwardTo: 'alice@example.org' }, { address: 'bob@dmcn.email' }],
      ['alice@dmcn.email', 'bob@dmcn.email'], 'me@dmcn.email',
    )).toEqual([{ forAddr: 'alice@dmcn.email', target: 'alice@example.org' }]);
  });

  it('skips a target that already gets the message, or is the sender', () => {
    expect(planForwardCopies(
      [{ address: 'alice@dmcn.email', forwardTo: 'Bob@dmcn.email' }, { address: 'carol@dmcn.email', forwardTo: 'me@dmcn.email' }],
      ['alice@dmcn.email', 'bob@dmcn.email', 'carol@dmcn.email'], 'me@dmcn.email',
    )).toEqual([]);
  });

  it('sends one copy when two recipients forward to the same place', () => {
    expect(planForwardCopies(
      [{ address: 'a@dmcn.email', forwardTo: 'x@example.org' }, { address: 'b@dmcn.email', forwardTo: 'X@example.org' }],
      ['a@dmcn.email', 'b@dmcn.email'], 'me@dmcn.email',
    )).toHaveLength(1);
  });

  it('follows one hop: only the recipients\' own forwards are read', () => {
    // b forwards to c, and b is the forwarding address of a; c is not reached through b.
    const plan = planForwardCopies(
      [{ address: 'a@dmcn.email', forwardTo: 'b@dmcn.email' }],
      ['a@dmcn.email'], 'me@dmcn.email',
    );
    expect(plan.map(p => p.target)).toEqual(['b@dmcn.email']);
  });
});

describe('wording', () => {
  const all = [
    forwardNotice('alice@dmcn.email', 'alice@example.org', 'dmcn'),
    forwardNotice('alice@dmcn.email', 'alice@example.org', 'email'),
    forwardNotice('alice@dmcn.email', 'alice@example.org', 'unknown'),
    forwardedOnlyMessage('alice@dmcn.email', 'alice@example.org'),
    forwardFailedMessage('alice@dmcn.email', 'alice@example.org'),
    forwardOnlyFailedMessage('alice@dmcn.email', 'alice@example.org'),
    forwardUnsendableNotice('alice@dmcn.email', 'alice@example.org'),
  ];

  it('names both addresses, in plain words', () => {
    for (const s of all) {
      expect(s).toContain('alice@dmcn.email');
      expect(s).toContain('alice@example.org');
      expect(s).not.toMatch(/—|forward_to|relay|bridge|SMTP|410/);
    }
  });

  it('says an email copy is not end-to-end encrypted, and a DMCN one is', () => {
    expect(forwardNotice('a@x', 'b@y', 'email')).toMatch(/not end-to-end encrypted/);
    expect(forwardNotice('a@x', 'b@y', 'dmcn')).toMatch(/end-to-end encrypted too/);
  });
});
