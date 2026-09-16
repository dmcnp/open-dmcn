// The one place new-mail notifications introduce themselves.
//
// Everything else about the feature waits to be found: the switch is in Settings → Account, and a
// person who never goes looking there never learns that their mail can reach them with the app
// closed. That is the wrong way round for the one capability that decides whether this is a mailbox
// you have to remember to check. So the question is put once, plainly, on the inbox that has just
// been unlocked — and then never again, whatever the answer.
//
// WHEN it may be asked at all is decided in push/offer.ts, away from the markup, because "never
// again" is the load-bearing half: a prompt that comes back is the one that gets a site's
// notifications blocked at the browser for good, and a browser-level block cannot be undone from
// here.

import { useCallback, useEffect, useState } from 'react';
import { deployment } from '@deployment';
import { Button, Dialog } from '../ds';
import type { WorkingKeys } from '../lib/crypto/workingKeys';
import { enableNotifications } from '../lib/push/enable';
import { offerFacts, rememberOfferAnswered, shouldOffer } from '../lib/push/offer';
import { scopeIdFor } from '../lib/push/scopes';
import { pushConfigured } from '../lib/push/subscription';

// Long enough for the mailbox to be on screen behind it. A dialog that arrives WITH the inbox reads
// as one more thing to get past on the way in; the same dialog a moment later is an offer about the
// mail already visible behind it, which is what it actually is.
const SETTLE_MS = 1_500;

// 'offer' asks; 'later' is what a decline leaves behind, which exists only to say where the switch
// lives for someone who changes their mind.
type Face = 'hidden' | 'offer' | 'later';

export function NotificationOffer({ address, keys }: { address: string; keys: WorkingKeys }) {
  const [face, setFace] = useState<Face>('hidden');
  const [scopeId, setScopeId] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    // A different account is a different question, and the answer to the last one was about a
    // different mailbox: a push tapped for another account switches this shell underneath an open
    // dialog (PushIntentRouter), and what is on screen must never outlive whose it was.
    setFace('hidden');
    setScopeId('');
    if (!pushConfigured() || !deployment.push) return;
    let cancelled = false;
    const timer = setTimeout(() => {
      void (async () => {
        try {
          const id = await scopeIdFor(keys.x25519Public);
          const facts = await offerFacts(id);
          if (cancelled || !shouldOffer(facts)) return;
          setScopeId(id);
          setFace('offer');
        } catch {
          // Whatever went wrong reading the browser's own state, an unasked question is the
          // harmless outcome. The settings card remains where this is turned on.
        }
      })();
    }, SETTLE_MS);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [address, keys]);

  // Every way out of this dialog is an answer — yes, not now, the × — and each one is final. A
  // failed attempt counts too: it was asked, it was seen, and the settings card is where a retry
  // belongs rather than the next unlock.
  const answer = useCallback(() => {
    if (scopeId) rememberOfferAnswered(scopeId);
  }, [scopeId]);

  async function turnOn() {
    setBusy(true);
    setErr('');
    try {
      await enableNotifications(address, keys);
      answer();
      setFace('hidden');
    } catch (e) {
      // Kept on screen with the reason. The buttons still work, so the way out is unchanged.
      setErr(e instanceof Error ? e.message : 'Could not turn notifications on.');
    } finally {
      setBusy(false);
    }
  }

  function decline() {
    answer();
    setFace('later');
  }

  // The × and Escape: an answer like any other, but someone dismissing a dialog wants it gone
  // rather than replaced with another one.
  function dismiss() {
    answer();
    setFace('hidden');
  }

  if (face === 'hidden') return null;

  if (face === 'later') {
    return (
      <Dialog
        open
        onClose={() => setFace('hidden')}
        title="Notifications stay off"
        footer={<Button onClick={() => setFace('hidden')}>Got it</Button>}
      >
        <div style={{ lineHeight: 'var(--leading-normal)' }}>
          You can turn them on for this account at any time in Settings → Account → Notifications.
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      open
      onClose={dismiss}
      title="Would you like to be notified of new emails?"
      footer={
        <>
          <Button variant="secondary" onClick={decline} disabled={busy}>Not now</Button>
          <Button onClick={() => void turnOn()} disabled={busy}>
            {busy ? 'Working…' : 'Turn notifications on'}
          </Button>
        </>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', lineHeight: 'var(--leading-normal)' }}>
        {/* What the notification can say is not a setting anyone could change later — the relay
            that sends it holds no key to the mail it is telling you about. Said as the limit it
            is, rather than as the mechanism behind it. */}
        <div>
          We can’t tell you who sent the mail or what’s in it, because we can’t see that. But we can
          tell you that a new email arrived and let you handle it from there.
        </div>
        <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)' }}>
          For <strong style={{ color: 'var(--text-body)', fontWeight: 'var(--weight-medium)' }}>{address}</strong>, on this device.
        </div>
        {err && <div role="alert" style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)' }}>{err}</div>}
      </div>
    </Dialog>
  );
}
