import { describe, it, expect } from 'vitest';
import { BridgeTrustTier, type BridgeAttestation } from '../crypto/bridgeAttest';
import { messageChecks, type ChecksInput, type MessageChecksView } from './checks';

// The checks strip has to say the same thing the reader's gate does. A tick on a word the gate
// treats as failed, or a cross on a verdict it treats as fine, teaches the reader that the strip
// cannot be relied on — so these pin which words cross, and when a notice appears, per verdict.

const base: ChecksInput = {
  address: 'ada@dmcn.me',
  name: 'Ada Okafor',
  recipients: 1,
  own: false,
  attestation: null,
  receipt: null,
  trust: null,
};

function bridged(over: Partial<BridgeAttestation>): BridgeAttestation {
  return { verified: true, trustTier: BridgeTrustTier.VerifiedLegacy, smtpFrom: 'ds@stern.nyu.edu', spf: 'pass', dkim: 'pass', dmarc: 'pass', ...over };
}

const words = (v: MessageChecksView) => v.checks.map(c => `${c.ok ? '+' : '-'}${c.word}`).join(' ');

describe('messageChecks: regular email', () => {
  it('shows four ticks and no notice when every check passed', () => {
    const v = messageChecks({ ...base, address: 'ds@stern.nyu.edu', attestation: bridged({}) });
    expect(v.source).toMatchObject({ kind: 'regular', label: 'Regular email' });
    expect(words(v)).toBe('+Origin +Domain +Sender +Encrypted');
    expect(v.notice).toBeUndefined();
    expect(v.checks[0].tip).toBe('Sent from a mail server that stern.nyu.edu allows. (SPF)');
  });

  it('crosses the three checks and says the address was used when DMARC failed', () => {
    const v = messageChecks({
      ...base, address: 'service@paypal.com',
      attestation: bridged({ trustTier: BridgeTrustTier.Suspicious, smtpFrom: 'x@evil.example', spf: 'fail', dkim: 'none', dmarc: 'fail' }),
    });
    expect(words(v)).toBe('-Origin -Domain -Sender +Encrypted');
    expect(v.notice).toEqual({ tone: 'danger', text: 'This did not come from paypal.com. Someone used their address. Do not click links or reply.' });
    // SPF asked the envelope's domain, not the From domain, so that is the one it names.
    expect(v.checks[0].tip).toBe('Sent from a mail server that evil.example does not allow. (SPF)');
  });

  it('names the envelope domain and on whose behalf when bulk mail passes through a provider', () => {
    const v = messageChecks({ ...base, address: 'noreply@reddit.com', attestation: bridged({ smtpFrom: 'b@amazonses.com' }) });
    expect(v.checks[0].tip).toBe('Sent from a mail server that amazonses.com allows, on behalf of reddit.com. (SPF)');
  });

  it('warns without claiming forgery when the domain could not confirm it', () => {
    const v = messageChecks({ ...base, address: 'a@small.example', attestation: bridged({ trustTier: BridgeTrustTier.UnverifiedLegacy, smtpFrom: 'a@small.example', spf: 'none', dkim: 'none', dmarc: 'none' }) });
    expect(words(v)).toBe('-Origin -Domain -Sender +Encrypted');
    expect(v.notice?.tone).toBe('danger');
    expect(v.notice?.text).toMatch(/^small\.example could not confirm this came from them/);
  });

  it('does not claim forgery for a broken signature alone', () => {
    const v = messageChecks({ ...base, address: 'a@small.example', attestation: bridged({ trustTier: BridgeTrustTier.Suspicious, smtpFrom: 'a@small.example', dkim: 'fail', dmarc: 'none' }) });
    expect(words(v)).toBe('+Origin -Domain -Sender +Encrypted');
    expect(v.notice?.text).toMatch(/^small\.example could not confirm this came from them/);
  });

  it('marks a single failed word but raises no notice under a verified tier', () => {
    // A forwarded message: SPF fails at the forwarder, aligned DKIM carries DMARC.
    const v = messageChecks({ ...base, address: 'ds@stern.nyu.edu', attestation: bridged({ spf: 'fail' }) });
    expect(words(v)).toBe('-Origin +Domain +Sender +Encrypted');
    expect(v.notice).toBeUndefined();
  });

  it('trusts none of the claimed results when the bridge itself did not verify', () => {
    const v = messageChecks({ ...base, attestation: bridged({ verified: false, reason: 'untrusted bridge' }) });
    expect(words(v)).toBe('-Origin -Domain -Sender +Encrypted');
    expect(v.notice?.tone).toBe('danger');
  });
});

describe('messageChecks: dmcn mail', () => {
  it('shows a trusted contact with four ticks', () => {
    const v = messageChecks({ ...base, trust: { kind: 'allowlisted', provenance: 'user_approved' } });
    expect(v.source).toMatchObject({ kind: 'contact', label: 'Trusted contact' });
    expect(words(v)).toBe('+Sender +Domain +Origin +Encrypted');
    expect(v.notice).toBeUndefined();
  });

  it('shows a domain-verified stranger as dmcn mail with four ticks', () => {
    const v = messageChecks({ ...base, trust: { kind: 'domain_verified' } });
    expect(v.source).toMatchObject({ kind: 'dmcn', label: 'dmcn mail' });
    expect(words(v)).toBe('+Sender +Domain +Origin +Encrypted');
  });

  it('crosses Sender only, with the pinned-key sentence, when a contact’s key changed', () => {
    const v = messageChecks({ ...base, trust: { kind: 'key_changed' }, keyChange: { kind: 'unexplained' } });
    expect(v.source.kind).toBe('dmcn');
    expect(words(v)).toBe('-Sender +Domain +Origin +Encrypted');
    expect(v.notice?.tone).toBe('danger');
    expect(v.notice?.text).toMatch(/^The key for Ada Okafor has changed since you verified them/);
  });

  it('crosses Sender and Domain when the directory disowns the signing key', () => {
    const v = messageChecks({ ...base, trust: { kind: 'key_mismatch' } });
    expect(words(v)).toBe('-Sender -Domain +Origin +Encrypted');
    expect(v.notice?.tone).toBe('danger');
  });

  it('keeps every tick but raises a warning when only a record property changed', () => {
    const v = messageChecks({ ...base, trust: { kind: 'record_changed', reason: 'this contact’s key custody by their provider changed since you verified them' } });
    expect(words(v)).toBe('+Sender +Domain +Origin +Encrypted');
    expect(v.notice?.tone).toBe('warning');
    expect(v.notice?.text).toMatch(/^This contact’s key custody/);
  });

  it('says only you can read it, or you and the others, by the audience', () => {
    const one = messageChecks({ ...base, trust: { kind: 'domain_verified' } });
    const many = messageChecks({ ...base, recipients: 3, trust: { kind: 'domain_verified' } });
    expect(one.checks[3].tip).toBe('Encrypted end to end. Only you can read it.');
    expect(many.checks[3].tip).toBe('Encrypted end to end. Only you and the other recipients can read it.');
  });
});

describe('messageChecks: own mail and receipts', () => {
  it('describes a Sent copy without checks about a sender', () => {
    const v = messageChecks({ ...base, own: true, trust: { kind: 'key_mismatch' } });
    expect(v.source.kind).toBe('own');
    expect(words(v)).toBe('+Encrypted');
    expect(v.notice).toBeUndefined();
  });

  it('carries a failed delivery as a danger notice', () => {
    const v = messageChecks({ ...base, receipt: { verified: true, delivered: false, recipientEmail: 'bob@example.com', errorDetail: 'mailbox full' } });
    expect(v.source.kind).toBe('receipt');
    expect(v.notice).toEqual({ tone: 'danger', text: 'The bridge could not deliver your message to bob@example.com: mailbox full' });
  });
});
