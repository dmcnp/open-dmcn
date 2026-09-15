// Sending a tapped notification to the account it was about.
//
// A notification names nobody, but it does know which account it woke, and landing in the wrong
// mailbox — or in a generic inbox — would waste the one thing it can say. Two ways in: the worker
// focuses an open window and posts the account id, or it opens a new one at a URL carrying it,
// which main.tsx parks before the router can drop the query string.
//
// Three destinations, in order of how much the person has to do:
//
//   - already this account: nothing but a nudge to the inbox.
//   - unlocked, not in front: switch, with no prompt — the handle is already here.
//   - locked, or signed out: the unlock screen, with that account picked out. The intent is left
//     in place for Login to consume, because only Login can show it.
//
// With one thing held back: an unsent message. Switching accounts discards a draft, so a tap must
// never do it silently. The intent stays parked and is honoured the moment the compose window
// closes, which is the one reading that loses nobody's work.
//
// What it deliberately does NOT do is unlock anything by itself. A passkey prompt needs a real
// user gesture, and a service worker's activation does not carry into a fresh document — Safari
// refuses it outright. The person taps Unlock, as they would have anyway.

import { useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../lib/hooks/useAuth';
import { useKeys } from '../lib/hooks/useKeys';
import { useAccountSwitch } from '../lib/hooks/useAccountSwitch';
import { accountForScope } from '../lib/push/whichAccount';
import { peekIntent, takeIntent, setIntent } from '../lib/push/intent';
import { isDraftOpen, onDraftOpenChange } from '../lib/draftOpen';

export function PushIntentRouter() {
  const { address } = useAuth();
  const { keys } = useKeys();
  const { switchTo } = useAccountSwitch();
  const navigate = useNavigate();
  const location = useLocation();
  // Guards the effect against re-running itself: routing to /login leaves the intent in place on
  // purpose, and without this the navigation would feed straight back in.
  const handling = useRef(false);

  useEffect(() => {
    const handle = async () => {
      if (handling.current || !peekIntent()) return;
      handling.current = true;
      try {
        const id = peekIntent()!;
        const account = await accountForScope(id);
        if (!account) { takeIntent(); return; } // an account this context does not hold
        if (account.address === address && keys) {
          takeIntent();
          if (location.pathname !== '/inbox') navigate('/inbox');
          return;
        }
        if (account.unlocked) {
          // Wait rather than discard. handle() runs again when the draft closes.
          if (isDraftOpen()) return;
          takeIntent();
          await switchTo(account);
          return;
        }
        // Locked: Login is the only screen that can offer the unlock, so leave the intent for it.
        if (location.pathname !== '/login') navigate('/login');
      } finally {
        handling.current = false;
      }
    };

    void handle();

    // The same decision, arriving live because the worker focused a window that was already open.
    const onMessage = (e: MessageEvent) => {
      const data = e.data as { type?: string; scopeId?: string } | null;
      if (data?.type !== 'dmcn:push-intent' || !data.scopeId) return;
      setIntent(data.scopeId);
      void handle();
    };
    // A deferred switch is owed as soon as the draft is gone.
    const stopWatchingDraft = onDraftOpenChange(() => { if (!isDraftOpen()) void handle(); });

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.addEventListener('message', onMessage);
      return () => {
        stopWatchingDraft();
        navigator.serviceWorker.removeEventListener('message', onMessage);
      };
    }
    return stopWatchingDraft;
  }, [address, keys, switchTo, navigate, location.pathname]);

  return null;
}
