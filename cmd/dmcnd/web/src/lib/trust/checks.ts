// The reader's checks strip: what was established about a received message, as four plain words
// with a tick or a cross — Origin, Domain, Sender, Encrypted — and one sentence underneath when
// something did not hold.
//
// The words are the same for both kinds of mail so a reader learns them once, but what stands
// behind each differs, and the tip on every word says which:
//
//               regular email (via a bridge)              dmcn mail
//   Origin      SPF: a server the domain allows sent it    sent over dmcn, no regular email hop
//   Domain      DKIM: signed, and unchanged since          the domain lists the key that signed it
//   Sender      DMARC: the From address is the domain's    the key is the one you have on file
//   Encrypted   sealed to you by a bridge you trust        end to end
//
// This module only DESCRIBES. Whether the body is gated, shown as text or rendered is decided in
// MessageReader from the same facts; a cross here never opens or closes anything by itself.
//
// Copy rules (security-warning-copy): plain words, no protocol mechanics in the sentence (the
// acronym rides in brackets on the tip, for the people who look for it), never a speculation the
// reader cannot act on.

import { BridgeTrustTier, type BridgeAttestation } from '../crypto/bridgeAttest';
import type { DeliveryReceiptView } from '../crypto/receiptAttest';
import type { SenderTrust } from '../crypto/senderTrust';
import type { KeyChange } from './lineage';
import { pinnedKeyWarning } from './pinnedKey';
import { provenanceView } from './trustView';

export type CheckWord = 'Origin' | 'Domain' | 'Sender' | 'Encrypted';

export interface Check {
  word: CheckWord;
  ok: boolean;
  tip: string;
}

/** Which network the message came over, and whether its sender is one of your contacts. */
export type SourceKind = 'regular' | 'dmcn' | 'contact' | 'own' | 'receipt';

export interface MessageChecksView {
  source: { kind: SourceKind; label: string; tip: string };
  checks: Check[];
  /** The one sentence a failed check earns. Danger for anything that may be forged. */
  notice?: { tone: 'danger' | 'warning' | 'neutral'; text: string };
}

export interface ChecksInput {
  /** The sender's address as the reader displays it. */
  address: string;
  /** How a sentence names the sender: the contact's name, the message's display name, or the address. */
  name: string;
  /** Everyone the message was addressed to besides the sender (To + Cc). */
  recipients: number;
  /** A message I wrote (a Sent copy, or mail to myself). */
  own: boolean;
  attestation: BridgeAttestation | null;
  receipt: DeliveryReceiptView | null;
  /** The native directory/allowlist verdict; null when none applies. */
  trust: SenderTrust | null;
  /** What the directory can prove about a changed key, once loaded. */
  keyChange?: KeyChange;
}

export function domainPart(addr: string): string {
  const at = (addr || '').lastIndexOf('@');
  return at >= 0 ? addr.slice(at + 1).toLowerCase() : '';
}

export function messageChecks(input: ChecksInput): MessageChecksView {
  if (input.own) return ownChecks(input);
  if (input.receipt) return receiptChecks(input.receipt);
  if (input.attestation) return bridgedChecks(input.attestation, input.address);
  return nativeChecks(input);
}

function ownChecks({ recipients }: ChecksInput): MessageChecksView {
  return {
    source: { kind: 'own', label: 'Sent by you', tip: 'You sent this message.' },
    checks: [{
      word: 'Encrypted', ok: true,
      tip: recipients > 0
        ? 'Your copy is encrypted so only you can read it.'
        : 'Encrypted so only you can read it.',
    }],
  };
}

function receiptChecks(r: DeliveryReceiptView): MessageChecksView {
  const who = r.recipientEmail || 'the recipient';
  if (!r.verified) {
    return {
      source: { kind: 'receipt', label: 'Delivery receipt', tip: 'A receipt for mail you sent to a regular email address.' },
      checks: [{ word: 'Sender', ok: false, tip: `This receipt could not be verified${r.reason ? ` (${r.reason})` : ''}.` }],
      notice: { tone: 'warning', text: 'This receipt could not be verified, so it may not say what really happened to your message.' },
    };
  }
  return {
    source: { kind: 'receipt', label: 'Delivery receipt', tip: 'A receipt for mail you sent to a regular email address.' },
    checks: [{ word: 'Sender', ok: true, tip: 'Signed by a dmcn bridge you trust.' }],
    notice: r.delivered
      ? { tone: 'neutral', text: `The bridge delivered your message to ${who}.` }
      : { tone: 'danger', text: `The bridge could not deliver your message to ${who}${r.errorDetail ? `: ${r.errorDetail}` : '.'}` },
  };
}

const BRIDGE_ENCRYPTED = 'A trusted dmcn bridge checked this email and encrypted it to you. Before the bridge it travelled as regular email.';

function bridgedChecks(a: BridgeAttestation, address: string): MessageChecksView {
  const source = {
    kind: 'regular' as const,
    label: 'Regular email',
    tip: 'Regular email. It reached dmcn through a bridge, which checked it on arrival.',
  };
  if (!a.verified) {
    // Nothing the record claims can be relied on, including which checks it says passed.
    const tip = `The bridge that carried this could not be verified${a.reason ? ` (${a.reason})` : ''}, so its checks cannot be relied on.`;
    return {
      source,
      checks: [
        { word: 'Origin', ok: false, tip },
        { word: 'Domain', ok: false, tip },
        { word: 'Sender', ok: false, tip },
        { word: 'Encrypted', ok: true, tip: 'Encrypted to you, by a bridge that could not be verified.' },
      ],
      notice: { tone: 'danger', text: `This came through a bridge that could not be verified, so nothing confirms it is from ${address || 'the sender'}. Do not click links or reply until you have checked with them another way.` },
    };
  }

  const from = domainPart(address) || domainPart(a.smtpFrom);
  // SPF checks the envelope sender, which bulk mail routes through its provider (From reddit.com,
  // envelope …@amazonses.com). Name the domain that was actually asked, and say on whose behalf.
  const envelope = domainPart(a.smtpFrom) || from;
  const via = envelope && from && envelope !== from ? `, on behalf of ${from}` : '';
  const spf = (a.spf ?? '').toLowerCase();
  const dkim = (a.dkim ?? '').toLowerCase();
  const dmarc = (a.dmarc ?? '').toLowerCase();

  const origin: Check = {
    word: 'Origin', ok: spf === 'pass',
    tip: spf === 'pass' ? `Sent from a mail server that ${envelope} allows${via}. (SPF)`
      : spf === 'fail' || spf === 'softfail' ? `Sent from a mail server that ${envelope} does not allow. (SPF)`
        : spf === 'neutral' ? `${envelope} does not say whether this mail server may send for it. (SPF)`
          : `${envelope || 'The sending domain'} does not list which mail servers may send for it. (SPF)`,
  };
  // The bridge accepts a valid signature from any domain here; alignment with the From address is
  // DMARC's question, which is the Sender check. So this one says "signed and unchanged", not whose.
  const domain: Check = {
    word: 'Domain', ok: dkim === 'pass',
    tip: dkim === 'pass' ? 'Signed by the mail system that sent it, and unchanged since. (DKIM)'
      : dkim === 'fail' ? 'Its signature does not match, so it may have been changed on the way. (DKIM)'
        : 'Not signed, so nothing shows it is unchanged since it was sent. (DKIM)',
  };
  const sender: Check = {
    word: 'Sender', ok: dmarc === 'pass',
    tip: dmarc === 'pass' ? `The From address really belongs to ${from}. (DMARC)`
      : dmarc === 'fail' ? `The From address does not belong to whoever sent this. (DMARC)`
        : `${from || 'The sending domain'} does not publish a way to confirm its From addresses. (DMARC)`,
  };
  const checks = [origin, domain, sender, { word: 'Encrypted' as const, ok: true, tip: BRIDGE_ENCRYPTED }];

  // The notice follows the bridge's signed tier, which is what the reader's gate follows too. A
  // single cross under a VerifiedLegacy tier (SPF failing on a forwarded message whose aligned
  // DKIM carried DMARC) is shown on its word but is not a reason to alarm anybody.
  if (a.trustTier === BridgeTrustTier.VerifiedLegacy) return { source, checks };
  // Only a DMARC failure says the From address is not theirs. The tier is Suspicious for a broken
  // DKIM signature or a hard SPF fail too, and neither of those proves who sent it.
  if (dmarc === 'fail') {
    return {
      source, checks,
      notice: { tone: 'danger', text: `This did not come from ${from || 'the domain it names'}. Someone used their address. Do not click links or reply.` },
    };
  }
  return {
    source, checks,
    notice: { tone: 'danger', text: `${from || 'The sending domain'} could not confirm this came from them, so anyone could have put ${address || 'this address'} on it. Do not click links or reply until you have checked with them another way.` },
  };
}

function nativeChecks({ address, name, recipients, trust, keyChange }: ChecksInput): MessageChecksView {
  const domain = domainPart(address) || 'their domain';
  const origin: Check = { word: 'Origin', ok: true, tip: 'Sent directly over dmcn, with no regular email involved.' };
  const encrypted: Check = {
    word: 'Encrypted', ok: true,
    tip: recipients > 1
      ? 'Encrypted end to end. Only you and the other recipients can read it.'
      : 'Encrypted end to end. Only you can read it.',
  };
  const dmcnSource = (tip: string) => ({ kind: 'dmcn' as const, label: 'dmcn mail', tip });
  // The domain lists the key that signed this header — true for every verdict that got as far as
  // comparing against a pin, since the directory check comes first (senderTrust.ts).
  const listed: Check = { word: 'Domain', ok: true, tip: `${domain} lists this key for ${address}.` };

  switch (trust?.kind) {
    case 'allowlisted': {
      const pv = trust.provenance ? provenanceView(trust.provenance) : { label: 'Trusted contact' };
      return {
        source: { kind: 'contact', label: pv.label, tip: `${pv.label}. ${name} is one of your contacts.` },
        checks: [
          { word: 'Sender', ok: true, tip: `Signed with the key you have on file for ${address}.` },
          listed, origin, encrypted,
        ],
      };
    }
    case 'domain_verified':
      return {
        source: dmcnSource(`dmcn mail. ${name} is not in your contacts yet.`),
        checks: [
          { word: 'Sender', ok: true, tip: `Signed with the key ${domain} vouches for. You have not added ${name} to your contacts yet.` },
          listed, origin, encrypted,
        ],
      };
    case 'unknown_pending':
      return {
        source: dmcnSource(`dmcn mail. ${name} is not in your contacts yet.`),
        checks: [
          { word: 'Sender', ok: true, tip: `Signed with the key listed for ${address}.` },
          { word: 'Domain', ok: false, tip: `${domain} has not vouched for ${address}.` },
          origin, encrypted,
        ],
        notice: { tone: 'warning', text: `${domain} has not vouched for ${address}, so the address alone does not show who runs it.` },
      };
    case 'record_changed':
      return {
        source: { kind: 'contact', label: 'Trusted contact', tip: `Trusted contact. ${name} is one of your contacts.` },
        checks: [
          { word: 'Sender', ok: true, tip: `Signed with the key you have on file for ${address}.` },
          listed, origin, encrypted,
        ],
        notice: {
          tone: 'warning',
          text: trust.reason
            ? `${trust.reason[0].toUpperCase()}${trust.reason.slice(1)}. Their keys are the same, so this really is from them. This was not a change they made, so check that it is expected.`
            : `Something about ${name}’s account changed since you verified them, though their keys are the same.`,
        },
      };
    case 'key_changed':
      return {
        source: dmcnSource(`dmcn mail. ${name} is one of your contacts. Their new key is waiting for your decision, so they show as a dmcn sender until you trust it.`),
        checks: [
          { word: 'Sender', ok: false, tip: `Signed with a new key, different from the one you have on file for ${address}.` },
          { word: 'Domain', ok: true, tip: `${domain} lists this new key for ${address}.` },
          origin, encrypted,
        ],
        // The same sentence the composer and the contact list show for the same event (pinnedKey.ts).
        notice: { tone: 'danger', text: pinnedKeyWarning(name, keyChange) },
      };
    case 'key_mismatch':
      return {
        source: dmcnSource(`dmcn mail, but not signed with ${address}’s key.`),
        checks: [
          { word: 'Sender', ok: false, tip: `Signed with a key ${domain} does not list for ${address}.` },
          { word: 'Domain', ok: false, tip: `${domain} lists a different key for ${address}.` },
          origin, encrypted,
        ],
        notice: { tone: 'danger', text: `This was not signed with the key ${domain} lists for ${address}. Someone may be using their address. Do not click links or reply until you have checked with them another way.` },
      };
    case 'identity_unverifiable':
      return {
        source: dmcnSource(`dmcn mail, from an address ${domain} no longer vouches for.`),
        checks: [
          { word: 'Sender', ok: false, tip: `${domain} no longer vouches for ${address}.` },
          { word: 'Domain', ok: false, tip: `${domain}’s approval of ${address} was withdrawn or does not check out.` },
          origin, encrypted,
        ],
        notice: { tone: 'danger', text: `${domain} no longer vouches for ${address}. Do not click links or reply until you have checked with them another way.` },
      };
    case 'directory_missing':
    default:
      return {
        source: dmcnSource('dmcn mail.'),
        checks: [
          { word: 'Sender', ok: false, tip: `Could not look up the key for ${address} just now.` },
          { word: 'Domain', ok: false, tip: `Could not reach ${domain} to check this key.` },
          origin, encrypted,
        ],
        notice: { tone: 'warning', text: `Could not look up ${address} just now, so who signed this cannot be confirmed yet.` },
      };
  }
}
