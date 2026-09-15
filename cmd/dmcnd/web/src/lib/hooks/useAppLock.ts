// Locking the app when you leave it.
//
// "Lock when I leave" has always described a tab CLOSING — the handles are keyed by a
// sessionStorage tab id, so they die with the window and nothing had to watch for it. Nothing
// watched for leaving in any other sense, which is the gap this closes: an installed app pushed to
// the background, or a tab abandoned on a shared machine, stayed unlocked indefinitely.
//
// A grace period, not an instant lock. Glancing at another tab to copy an address, or answering a
// notification, is leaving by every technical measure and by no human one — and a mail client that
// demanded a passkey each time would simply be turned off. Two minutes is long enough to come
// straight back and short enough that walking away locks.
//
// It locks every account this context holds, not just the one in front: they were all unlocked
// together, and leaving the machine leaves it for all of them.

import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { isLockOnLeave } from '../devicePosture';
import { useKeys } from './useKeys';
import { useAuth } from './useAuth';

export const LOCK_GRACE_MS = 2 * 60 * 1000;

export function useAppLock(): void {
  const { clearAllKeys } = useKeys();
  const { isAuthenticated, clearSession } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLockOnLeave() || !isAuthenticated) return;
    let timer: number | undefined;

    const cancel = () => {
      if (timer !== undefined) { window.clearTimeout(timer); timer = undefined; }
    };

    const lock = () => {
      cancel();
      void (async () => {
        await clearAllKeys();
        clearSession();
        navigate('/login', { state: { reason: 'locked' } });
      })();
    };

    const onVisibility = () => {
      if (document.visibilityState === 'visible') cancel();
      else {
        cancel();
        timer = window.setTimeout(lock, LOCK_GRACE_MS);
      }
    };

    document.addEventListener('visibilitychange', onVisibility);
    // Start counting if we mount already hidden — an app restored into the background, say.
    if (document.visibilityState !== 'visible') onVisibility();
    return () => {
      cancel();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [isAuthenticated, clearAllKeys, clearSession, navigate]);
}
